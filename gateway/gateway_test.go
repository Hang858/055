package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProxyAndCertificateVerification(t *testing.T) {
	dir := t.TempDir()
	if err := generatePKI(dir, "localhost,127.0.0.1", 1); err != nil {
		t.Fatal(err)
	}
	ca, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.RequestURI() != "/base/hello?q=1" || r.Header.Get("X-Forwarded-For") != "127.0.0.1" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-Port") != "" || r.Header.Get("X-Forwarded-Prefix") != "" {
			t.Errorf("bad forwarding: %s %v", r.URL, r.Header)
		}
		w.Header().Set("X-Backend", "ok")
		w.WriteHeader(201)
		w.Write(body)
	}))
	defer upstream.Close()
	testGroups := []string{"SM2Kyber512Draft00", "SM2Kyber768Draft00", "SM2Kyber1024Draft00", "X25519Kyber512Draft00", "X25519Kyber768Draft00", "X25519Kyber1024Draft00"}
	if tls.HQCEnabled() {
		testGroups = append(testGroups, "X25519HQC-128", "X25519HQC-256", "SM2HQC-128", "SM2HQC-256")
	}
	for _, group := range testGroups {
		t.Run(group, func(t *testing.T) {
			cfg := Config{Listen: "127.0.0.1:0", Upstream: upstream.URL + "/base", Cert: filepath.Join(dir, "server.crt"), Key: filepath.Join(dir, "server.key"), KEX: []string{group}}
			server, err := newGateway(cfg)
			if err != nil {
				t.Fatal(err)
			}
			ts := httptest.NewUnstartedServer(server.Handler)
			ts.TLS = server.TLSConfig
			ts.StartTLS()
			defer ts.Close()
			curves, _ := selectGroups([]string{group})
			tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, CurvePreferences: curves, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			req, _ := http.NewRequest("POST", ts.URL+"/hello?q=1", strings.NewReader("factory-payload"))
			req.Header.Set("X-Forwarded-For", "spoofed")
			req.Header.Set("Forwarded", "spoofed")
			req.Header.Set("X-Forwarded-Port", "444")
			req.Header.Set("X-Forwarded-Prefix", "/spoofed")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 201 || string(body) != "factory-payload" || resp.Header.Get("X-Backend") != "ok" || resp.TLS.Version != tls.VersionTLS13 {
				t.Fatalf("bad response: %d %q", resp.StatusCode, body)
			}
			for name, tlsCfg := range map[string]*tls.Config{
				"untrusted CA":          {CurvePreferences: curves},
				"wrong hostname":        {RootCAs: roots, CurvePreferences: curves, ServerName: "wrong.factory"},
				"expired certificate":   {RootCAs: roots, CurvePreferences: curves, Time: func() time.Time { return time.Now().Add(48 * time.Hour) }},
				"classical-only client": {RootCAs: roots, CurvePreferences: []tls.CurveID{tls.X25519}},
				"TLS 1.2 client":        {RootCAs: roots, CurvePreferences: curves, MaxVersion: tls.VersionTLS12},
			} {
				badTr := &http.Transport{TLSClientConfig: tlsCfg}
				defer badTr.CloseIdleConnections()
				badClient := &http.Client{Transport: badTr, Timeout: 5 * time.Second}
				if r, err := badClient.Get(ts.URL); err == nil {
					r.Body.Close()
					t.Errorf("accepted %s", name)
				}
			}
		})
	}
	if err := generatePKI(dir, "localhost", 1); err == nil {
		t.Fatal("overwrote existing PKI")
	}
}

func TestConfigRejectsInvalidInputs(t *testing.T) {
	for _, data := range []string{
		`{}`, `{"unknown":true}`, `{} {}`, `{"listen":":8443","upstream":"file:///etc/passwd","cert":"a","key":"b","kex":["SM2Kyber512Draft00"]}`,
		`{"listen":":8443","upstream":"http://localhost:9000","cert":"a","key":"b","kex":["X25519"]}`,
	} {
		p := filepath.Join(t.TempDir(), "gateway.json")
		os.WriteFile(p, []byte(data), 0600)
		if _, err := loadConfig(p); err == nil {
			t.Errorf("accepted invalid config %s", data)
		}
	}
	if _, err := selectGroups([]string{"", "bogus"}); err == nil {
		t.Fatal("accepted unknown group")
	}
}

func TestHTTPSUpstreamAndFailure(t *testing.T) {
	dir := t.TempDir()
	if err := generatePKI(dir, "localhost,127.0.0.1", 1); err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "verified upstream") }))
	defer backend.Close()
	cfg := Config{Listen: ":8443", Upstream: backend.URL, Cert: filepath.Join(dir, "server.crt"), Key: filepath.Join(dir, "server.key"), KEX: []string{"SM2Kyber512Draft00"}}
	s, err := newGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "https://localhost/", nil))
	if rec.Code != 502 {
		t.Fatalf("untrusted upstream returned %d", rec.Code)
	}
	backendCA := filepath.Join(dir, "backend-ca.crt")
	os.WriteFile(backendCA, pemCertificate(backend.Certificate().Raw), 0600)
	cfg.UpstreamCA = backendCA
	s, err = newGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	s.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "https://localhost/", nil))
	if rec.Code != 200 || rec.Body.String() != "verified upstream" {
		t.Fatalf("trusted upstream returned %d %q", rec.Code, rec.Body.String())
	}
}

func TestMutualTLSRequiresTrustedClient(t *testing.T) {
	dir := t.TempDir()
	if err := generatePKI(dir, "127.0.0.1,localhost", 1); err != nil {
		t.Fatal(err)
	}
	ca, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "mtls-ok") }))
	defer backend.Close()
	cfg := Config{Listen: "127.0.0.1:0", Upstream: backend.URL, Cert: filepath.Join(dir, "server.crt"), Key: filepath.Join(dir, "server.key"), ClientCA: filepath.Join(dir, "ca.crt"), KEX: []string{"SM2Kyber512Draft00"}}
	s, err := newGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(s.Handler)
	ts.TLS = s.TLSConfig
	ts.StartTLS()
	defer ts.Close()
	curves, _ := selectGroups(cfg.KEX)
	clientCert, err := tls.LoadX509KeyPair(filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err = generatePKI(other, "localhost", 1); err != nil {
		t.Fatal(err)
	}
	wrongCert, err := tls.LoadX509KeyPair(filepath.Join(other, "client.crt"), filepath.Join(other, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		certs []tls.Certificate
		ok    bool
	}{
		{"missing client", nil, false}, {"untrusted client", []tls.Certificate{wrongCert}, false}, {"trusted client", []tls.Certificate{clientCert}, true},
	} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, CurvePreferences: curves, Certificates: test.certs}}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(ts.URL)
		if err != nil {
			if test.ok {
				t.Errorf("%s: %v", test.name, err)
			}
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !test.ok || string(body) != "mtls-ok" {
			t.Errorf("%s unexpectedly returned %d %q", test.name, resp.StatusCode, body)
		}
	}
}

func TestHQCGroupAvailability(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   tls.CurveID
	}{
		{"X25519HQC-128", tls.X25519HQC128}, {"X25519HQC-256", tls.X25519HQC256},
		{"SM2HQC-128", tls.SM2HQC128}, {"SM2HQC-256", tls.SM2HQC256},
	} {
		ids, err := selectGroups([]string{tc.name})
		if tls.HQCEnabled() {
			if err != nil || len(ids) != 1 || ids[0] != tc.id {
				t.Errorf("%s not enabled: %v %v", tc.name, ids, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "pq_hqc") {
			t.Errorf("%s needs a clear unavailable-build error, got %v", tc.name, err)
		}
	}
}
