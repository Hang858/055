package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func pemCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Issuing a new identity must never overwrite an existing certificate or key.
func generatePKI(dir, hosts string, days int) error {
	if days < 1 || days > 3650 {
		return fmt.Errorf("days must be between 1 and 3650")
	}
	var dns []string
	var ips []net.IP
	for _, h := range strings.Split(hosts, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			return fmt.Errorf("hosts must contain DNS names or IPs")
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			if strings.ContainsAny(h, " /:\\") {
				return fmt.Errorf("invalid DNS name %q", h)
			}
			dns = append(dns, h)
		}
	}
	// t.TempDir callers may pass an existing empty directory. Nonempty directories are always rejected.
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return fmt.Errorf("output directory is not empty: %s", dir)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	serial := func() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
	now := time.Now().Add(-5 * time.Minute)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caSerial, err := serial()
	if err != nil {
		return err
	}
	ca := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "Factory PQC Gateway Local CA"}, NotBefore: now, NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	write := func(name string, data []byte, mode os.FileMode) error {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	writeKey := func(name string, key *ecdsa.PrivateKey) error {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		return write(name, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
	}
	if err = write("ca.crt", pemCertificate(caDER), 0644); err != nil {
		return err
	}
	if err = writeKey("ca.key", caKey); err != nil {
		return err
	}
	for _, role := range []string{"server", "client"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		sn, err := serial()
		if err != nil {
			return err
		}
		cert := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: "Factory PQC Gateway " + role}, NotBefore: now, NotAfter: now.AddDate(0, 0, days), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
		if role == "server" {
			cert.DNSNames = dns
			cert.IPAddresses = ips
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		if err = write(role+".crt", pemCertificate(der), 0644); err != nil {
			return err
		}
		if err = writeKey(role+".key", key); err != nil {
			return err
		}
	}
	return nil
}
