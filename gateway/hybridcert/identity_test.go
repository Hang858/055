package hybridcert

import (
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pqc-gateway/hybridsig"
)

var fixtureTime = time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)

func TestLoadCertificateToolIdentity(t *testing.T) {
	for _, tc := range []struct {
		directory string
		level     hybridsig.Level
	}{
		{"44", hybridsig.Level128}, {"87", hybridsig.Level256},
	} {
		t.Run(tc.directory, func(t *testing.T) {
			dir := filepath.Join("testdata", tc.directory)
			id, err := Load(filepath.Join(dir, "root.crt"), filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "server.pq.key"), tc.level, Server, "gateway.factory.local", fixtureTime)
			if err != nil {
				t.Fatal(err)
			}
			message := []byte("TLS 1.3 CertificateVerify signed content")
			sig, err := hybridsig.Sign(tc.level, id.SM2Private, id.PQPrivate, message)
			if err != nil {
				t.Fatal(err)
			}
			if err := hybridsig.Verify(tc.level, id.SM2Public, id.PQPublic, message, sig); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(filepath.Join(dir, "root.crt"), filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "server.pq.key"), tc.level, Server, "wrong.factory.local", fixtureTime); err == nil {
				t.Error("accepted wrong DNS name")
			}
			if _, err := Load(filepath.Join(dir, "root.crt"), filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "server.pq.key"), tc.level, Server, "127.0.0.1", fixtureTime); err != nil {
				t.Errorf("valid IP SAN: %v", err)
			}
			if _, err := Load(filepath.Join(dir, "root.crt"), filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "server.pq.key"), tc.level, Client, "", fixtureTime); err == nil {
				t.Error("accepted server certificate for client authentication")
			}
			if _, err := Load(filepath.Join(dir, "root.crt"), filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"), filepath.Join(dir, "client.pq.key"), tc.level, Client, "", fixtureTime); err != nil {
				t.Fatalf("valid client identity: %v", err)
			}
			if _, err := Load(filepath.Join(dir, "root.crt"), filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "server.pq.key"), tc.level, Server, "gateway.factory.local", fixtureTime.AddDate(2, 0, 0)); err == nil {
				t.Error("accepted expired certificate")
			}
		})
	}
}

func TestLoadChainWithIntermediate(t *testing.T) {
	dir := filepath.Join("testdata", "intermediate44")
	_, err := LoadChain(filepath.Join(dir, "root.crt"), []string{filepath.Join(dir, "ca.crt")}, filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "server.pq.key"), hybridsig.Level128, Server, "gateway.factory.local", fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "root.crt"), filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "server.pq.key"), hybridsig.Level128, Server, "gateway.factory.local", fixtureTime); err == nil {
		t.Error("accepted leaf without its intermediate CA")
	}
}

func TestLoadRejectsMissingOrCorruptSignatures(t *testing.T) {
	dir := filepath.Join("testdata", "44")
	root := filepath.Join(dir, "root.crt")
	key := filepath.Join(dir, "server.key")
	pqKey := filepath.Join(dir, "server.pq.key")
	der, err := readPEM(filepath.Join(dir, "server.crt"), "CERTIFICATE")
	if err != nil {
		t.Fatal(err)
	}
	var original certificate
	if _, err := asn1.Unmarshal(der, &original); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*certificate)
	}{
		{"missing PQ public key", func(c *certificate) {
			for i, ext := range c.TBS.Extensions {
				if ext.Id.Equal(oidPQPublic) {
					c.TBS.Extensions = append(c.TBS.Extensions[:i], c.TBS.Extensions[i+1:]...)
					return
				}
			}
		}},
		{"missing PQ signature", func(c *certificate) {
			for i, ext := range c.TBS.Extensions {
				if ext.Id.Equal(oidPQSignature) {
					c.TBS.Extensions = append(c.TBS.Extensions[:i], c.TBS.Extensions[i+1:]...)
					return
				}
			}
		}},
		{"corrupt PQ signature", func(c *certificate) {
			for i := range c.TBS.Extensions {
				if c.TBS.Extensions[i].Id.Equal(oidPQSignature) {
					c.TBS.Extensions[i].Value[len(c.TBS.Extensions[i].Value)-1] ^= 1
					return
				}
			}
		}},
		{"corrupt SM2 signature", func(c *certificate) {
			c.Signature.Bytes[len(c.Signature.Bytes)-1] ^= 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cert certificate
			if _, err := asn1.Unmarshal(der, &cert); err != nil {
				t.Fatal(err)
			}
			cert.TBS.Raw = nil
			tc.mutate(&cert)
			mutated, err := asn1.Marshal(cert)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "bad.crt")
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mutated}), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(root, path, key, pqKey, hybridsig.Level128, Server, "gateway.factory.local", fixtureTime); err == nil {
				t.Error("accepted certificate with missing or corrupt signature")
			}
		})
	}
}

func TestLoadRejectsMismatchedKeysAndCorruptCertificate(t *testing.T) {
	dir := filepath.Join("testdata", "44")
	other := filepath.Join("testdata", "87")
	if _, err := Load(filepath.Join(other, "root.crt"), filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "server.pq.key"), hybridsig.Level128, Server, "gateway.factory.local", fixtureTime); err == nil {
		t.Error("accepted unrelated trusted root")
	}
	if _, err := Load(filepath.Join(dir, "root.crt"), filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "server.pq.key"), hybridsig.Level256, Server, "gateway.factory.local", fixtureTime); err == nil {
		t.Error("accepted wrong ML-DSA parameter set")
	}
	if _, err := Load(filepath.Join(dir, "root.crt"), filepath.Join(dir, "server.crt"), filepath.Join(other, "server.key"), filepath.Join(dir, "server.pq.key"), hybridsig.Level128, Server, "gateway.factory.local", fixtureTime); err == nil {
		t.Error("accepted unrelated SM2 key")
	}
	if _, err := Load(filepath.Join(dir, "root.crt"), filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(other, "server.pq.key"), hybridsig.Level128, Server, "gateway.factory.local", fixtureTime); err == nil {
		t.Error("accepted unrelated PQ key")
	}
	data, err := os.ReadFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 1
	bad := filepath.Join(t.TempDir(), "bad.crt")
	if err := os.WriteFile(bad, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "root.crt"), bad, filepath.Join(dir, "server.key"), filepath.Join(dir, "server.pq.key"), hybridsig.Level128, Server, "gateway.factory.local", fixtureTime); err == nil {
		t.Error("accepted modified certificate")
	}
}
