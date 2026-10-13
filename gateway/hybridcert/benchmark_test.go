package hybridcert

import (
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"
	"testing"

	"pqc-gateway/hybridsig"
)

// BenchmarkMutualTLS measures a complete new TLS 1.3 handshake, including
// hybrid key exchange and both client and server certificate verification.
// Session tickets are disabled so every iteration performs both signatures.
func BenchmarkMutualTLS(b *testing.B) {
	type benchmarkCase struct {
		name  string
		level hybridsig.Level
		group tls.CurveID
	}
	cases := []benchmarkCase{
		{"SM2Kyber512_MLDSA44", hybridsig.Level128, tls.SM2Kyber512Draft00},
		{"SM2Kyber1024_MLDSA87", hybridsig.Level256, tls.SM2Kyber1024Draft00},
	}
	if tls.HQCEnabled() {
		cases = append(cases,
			benchmarkCase{"SM2HQC128_MLDSA44", hybridsig.Level128, tls.SM2HQC128},
			benchmarkCase{"SM2HQC256_MLDSA87", hybridsig.Level256, tls.SM2HQC256})
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			fixture := "44"
			if tc.level == hybridsig.Level256 {
				fixture = "87"
			}
			dir := filepath.Join("testdata", fixture)
			root := filepath.Join(dir, "root.crt")
			serverCert, err := ServerCertificate(root, nil, filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "server.pq.key"), tc.level, "gateway.factory.local")
			if err != nil {
				b.Fatal(err)
			}
			clientCert, err := ClientCertificate(root, nil, filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"), filepath.Join(dir, "client.pq.key"), tc.level)
			if err != nil {
				b.Fatal(err)
			}
			serverVerifier, err := NewServerVerifier(root, tc.level)
			if err != nil {
				b.Fatal(err)
			}
			clientVerifier, err := NewClientVerifier(root, tc.level)
			if err != nil {
				b.Fatal(err)
			}
			scheme, err := Scheme(tc.level)
			if err != nil {
				b.Fatal(err)
			}
			serverConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}, HybridAuthScheme: scheme, VerifyHybridClient: clientVerifier, ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: true, CurvePreferences: []tls.CurveID{tc.group}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			clientConfig := &tls.Config{Certificates: []tls.Certificate{clientCert}, ServerName: "gateway.factory.local", HybridAuthScheme: scheme, VerifyHybridServer: serverVerifier, SessionTicketsDisabled: true, CurvePreferences: []tls.CurveID{tc.group}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer listener.Close()
			serverDone := make(chan error, 1)
			go func() {
				for i := 0; i < b.N; i++ {
					conn, err := listener.Accept()
					if err != nil {
						serverDone <- err
						return
					}
					wrapped := tls.Server(conn, serverConfig)
					err = wrapped.Handshake()
					wrapped.Close()
					if err != nil {
						serverDone <- err
						return
					}
				}
				serverDone <- nil
			}()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				conn, err := tls.Dial("tcp", listener.Addr().String(), clientConfig)
				if err != nil {
					b.Fatal(fmt.Errorf("handshake %d: %w", i, err))
				}
				if conn.ConnectionState().HybridAuthScheme != scheme {
					b.Fatal("unexpected signature scheme")
				}
				conn.Close()
			}
			b.StopTimer()
			if err := <-serverDone; err != nil {
				b.Fatal(err)
			}
		})
	}
}
