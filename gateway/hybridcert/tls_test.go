package hybridcert

import (
	"crypto"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"pqc-gateway/hybridsig"
)

type damagedSigner struct {
	*TLSSigner
	part string
}

func (s *damagedSigner) Sign(r io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := s.TLSSigner.Sign(r, message, opts)
	if err != nil {
		return nil, err
	}
	scheme, _, _ := schemeFor(s.Level)
	switch s.part {
	case "pq":
		sig[len(sig)-1] ^= 1
	case "sm2":
		sig[5] ^= 1
	case "missing-pq":
		sig = sig[:len(sig)-scheme.SignatureSize()]
	case "missing-sm2":
		sig = sig[len(sig)-scheme.SignatureSize():]
	}
	return sig, nil
}

func runHybridHandshake(t *testing.T, serverConfig, clientConfig *tls.Config) (error, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		serverDone <- tls.Server(conn, serverConfig).Handshake()
	}()
	client, clientErr := tls.Dial("tcp", listener.Addr().String(), clientConfig)
	if client != nil {
		client.Close()
	}
	return <-serverDone, clientErr
}

func TestHybridTLS13ServerAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name          string
		level         int
		intermediates []string
	}{
		{"44", 128, nil}, {"87", 256, nil}, {"intermediate44", 128, []string{"ca.crt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join("testdata", tc.name)
			level := hybridsig.Level(tc.level)
			var intermediates []string
			for _, name := range tc.intermediates {
				intermediates = append(intermediates, filepath.Join(dir, name))
			}
			certificate, err := ServerCertificate(filepath.Join(dir, "root.crt"), intermediates, filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "server.pq.key"), level, "gateway.factory.local")
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := NewServerVerifier(filepath.Join(dir, "root.crt"), level)
			if err != nil {
				t.Fatal(err)
			}
			scheme, _ := Scheme(level)
			serverConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, HybridAuthScheme: scheme, SessionTicketsDisabled: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			clientConfig := &tls.Config{ServerName: "gateway.factory.local", HybridAuthScheme: scheme, VerifyHybridServer: verifier, SessionTicketsDisabled: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			serverErr, clientErr := runHybridHandshake(t, serverConfig, clientConfig)
			if serverErr != nil || clientErr != nil {
				t.Fatalf("server=%v client=%v", serverErr, clientErr)
			}
			for _, part := range []string{"pq", "sm2", "missing-pq", "missing-sm2"} {
				t.Run("tampered-"+part, func(t *testing.T) {
					broken := serverConfig.Clone()
					brokenCert := certificate
					brokenCert.PrivateKey = &damagedSigner{certificate.PrivateKey.(*TLSSigner), part}
					broken.Certificates = []tls.Certificate{brokenCert}
					_, clientErr := runHybridHandshake(t, broken, clientConfig)
					if clientErr == nil || !strings.Contains(clientErr.Error(), "hybrid server authentication failed") {
						t.Fatalf("tampered %s accepted or wrong error: %v", part, clientErr)
					}
				})
			}
			wrong := clientConfig.Clone()
			if level == hybridsig.Level128 {
				wrong.HybridAuthScheme = tls.SM2WithMLDSA87
			} else {
				wrong.HybridAuthScheme = tls.SM2WithMLDSA44
			}
			_, clientErr = runHybridHandshake(t, serverConfig, wrong)
			if clientErr == nil {
				t.Fatal("accepted mismatched signature level")
			}
			traditional := clientConfig.Clone()
			traditional.HybridAuthScheme = 0
			traditional.VerifyHybridServer = nil
			traditional.InsecureSkipVerify = true
			_, clientErr = runHybridHandshake(t, serverConfig, traditional)
			if clientErr == nil {
				t.Fatal("accepted traditional authentication downgrade")
			}
			noVerifier := clientConfig.Clone()
			noVerifier.VerifyHybridServer = nil
			_, clientErr = runHybridHandshake(t, serverConfig, noVerifier)
			if clientErr == nil || errors.Is(clientErr, io.EOF) {
				t.Fatalf("missing verifier was not rejected explicitly: %v", clientErr)
			}
		})
	}
}
