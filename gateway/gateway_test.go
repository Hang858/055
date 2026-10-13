package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pqc-gateway/hybridcert"
	"pqc-gateway/hybridsig"
)

func TestHybridGatewayProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hybrid-gateway-ok")
	}))
	defer backend.Close()
	for _, tc := range []struct {
		name    string
		fixture string
		auth    string
		level   hybridsig.Level
		kex     string
	}{
		{"44-kyber", "44", "sm2-mldsa-44", hybridsig.Level128, "SM2Kyber512Draft00"},
		{"87-kyber", "87", "sm2-mldsa-87", hybridsig.Level256, "SM2Kyber1024Draft00"},
		{"44-mlkem", "44", "sm2-mldsa-44", hybridsig.Level128, "SM2MLKEM512"},
		{"87-mlkem", "87", "sm2-mldsa-87", hybridsig.Level256, "SM2MLKEM1024"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join("hybridcert", "testdata", tc.fixture)
			cfg := Config{Listen: "127.0.0.1:0", Upstream: backend.URL, Auth: tc.auth, Cert: filepath.Join(dir, "server.crt"), Key: filepath.Join(dir, "server.key"), PQKey: filepath.Join(dir, "server.pq.key"), RootCA: filepath.Join(dir, "root.crt"), ServerName: "gateway.factory.local", KEX: []string{tc.kex}}
			server, err := newGateway(cfg)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			go server.Serve(tls.NewListener(listener, server.TLSConfig))
			gatewayURL := "https://" + listener.Addr().String()
			verifier, err := hybridcert.NewServerVerifier(cfg.RootCA, tc.level)
			if err != nil {
				t.Fatal(err)
			}
			scheme, _ := hybridcert.Scheme(tc.level)
			curves, _ := selectGroups(cfg.KEX)
			clientConfig := &tls.Config{ServerName: cfg.ServerName, HybridAuthScheme: scheme, VerifyHybridServer: verifier, SessionTicketsDisabled: true, CurvePreferences: curves, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			transport := &http.Transport{TLSClientConfig: clientConfig}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			response, err := client.Get(gatewayURL)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != 200 || string(body) != "hybrid-gateway-ok" || response.TLS.Version != tls.VersionTLS13 || response.TLS.HybridAuthScheme != scheme || len(response.TLS.HybridPeerCertificates) != 1 {
				t.Fatalf("unexpected response %d %q", response.StatusCode, body)
			}
			if err := run([]string{"probe", "-url", gatewayURL, "-ca", cfg.RootCA, "-auth", tc.auth, "-server-name", cfg.ServerName, "-kex", tc.kex}); err != nil {
				t.Fatalf("hybrid probe: %v", err)
			}
			wrong := clientConfig.Clone()
			wrong.ServerName = "wrong.factory.local"
			wrongTransport := &http.Transport{TLSClientConfig: wrong}
			defer wrongTransport.CloseIdleConnections()
			if response, err := (&http.Client{Transport: wrongTransport, Timeout: 5 * time.Second}).Get(gatewayURL); err == nil {
				response.Body.Close()
				t.Fatal("accepted wrong server name")
			}
			if strings.HasSuffix(tc.name, "mlkem") {
				legacy := clientConfig.Clone()
				legacy.CurvePreferences, _ = selectGroups([]string{map[string]string{
					"44-mlkem": "SM2Kyber512Draft00",
					"87-mlkem": "SM2Kyber1024Draft00",
				}[tc.name]})
				legacyTransport := &http.Transport{TLSClientConfig: legacy}
				defer legacyTransport.CloseIdleConnections()
				if response, err := (&http.Client{Transport: legacyTransport, Timeout: 5 * time.Second}).Get(gatewayURL); err == nil {
					response.Body.Close()
					t.Fatal("accepted a legacy Kyber client for an ML-KEM-only gateway")
				}
			}
		})
	}
}

func TestHybridGatewayMutualTLS(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hybrid-mtls-ok")
	}))
	defer backend.Close()
	for _, tc := range []struct {
		name    string
		fixture string
		auth    string
		kex     string
	}{
		{"44-kyber", "44", "sm2-mldsa-44", "SM2Kyber512Draft00"},
		{"87-kyber", "87", "sm2-mldsa-87", "SM2Kyber1024Draft00"},
		{"44-mlkem", "44", "sm2-mldsa-44", "SM2MLKEM512"},
		{"87-mlkem", "87", "sm2-mldsa-87", "SM2MLKEM1024"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join("hybridcert", "testdata", tc.fixture)
			cfg := Config{Listen: "127.0.0.1:0", Upstream: backend.URL, Auth: tc.auth, Cert: filepath.Join(dir, "server.crt"), Key: filepath.Join(dir, "server.key"), PQKey: filepath.Join(dir, "server.pq.key"), RootCA: filepath.Join(dir, "root.crt"), ClientCA: filepath.Join(dir, "root.crt"), ServerName: "gateway.factory.local", KEX: []string{tc.kex}}
			server, err := newGateway(cfg)
			if err != nil {
				t.Fatal(err)
			}
			originalHandler := server.Handler
			server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || len(r.TLS.HybridPeerCertificates) != 1 || r.TLS.HybridAuthScheme != server.TLSConfig.HybridAuthScheme {
					t.Error("missing verified hybrid client identity in TLS connection state")
				}
				originalHandler.ServeHTTP(w, r)
			})
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			go server.Serve(tls.NewListener(listener, server.TLSConfig))
			url := "https://" + listener.Addr().String()
			base := []string{"probe", "-url", url, "-ca", cfg.RootCA, "-auth", tc.auth, "-server-name", cfg.ServerName, "-kex", tc.kex}
			if err := run(base); err == nil {
				t.Fatal("gateway accepted missing hybrid client identity")
			}
			args := append(append([]string(nil), base...), "-cert", filepath.Join(dir, "client.crt"), "-key", filepath.Join(dir, "client.key"), "-pq-key", filepath.Join(dir, "client.pq.key"))
			if err := run(args); err != nil {
				t.Fatalf("hybrid mTLS probe: %v", err)
			}
		})
	}
}

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
	testGroups := []string{"SM2MLKEM512", "SM2MLKEM1024", "SM2Kyber512Draft00", "SM2Kyber768Draft00", "SM2Kyber1024Draft00", "X25519Kyber512Draft00", "X25519Kyber768Draft00", "X25519Kyber1024Draft00"}
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

func TestHybridConfigRejectsIncompleteOrMixedAuthentication(t *testing.T) {
	valid := Config{Listen: ":8443", Upstream: "http://127.0.0.1:9000", Auth: "sm2-mldsa-44", Cert: "server.crt", Key: "server.key", PQKey: "server.pq.key", RootCA: "root.crt", ServerName: "gateway.factory.local", KEX: []string{"SM2Kyber512Draft00"}}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"missing PQ key", func(c *Config) { c.PQKey = "" }},
		{"missing root", func(c *Config) { c.RootCA = "" }},
		{"missing name", func(c *Config) { c.ServerName = "" }},
		{"unsupported auth", func(c *Config) { c.Auth = "dilithium" }},
		{"too many intermediates", func(c *Config) { c.Intermediates = []string{"1", "2", "3", "4", "5"} }},
		{"hybrid fields with traditional auth", func(c *Config) { c.Auth = "ecdsa" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.change(&c)
			if err := c.validate(); err == nil {
				t.Fatal("accepted invalid hybrid configuration")
			}
		})
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
