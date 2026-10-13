package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	gx "github.com/tjfoc/gmsm/x509"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"time"
)

type generatedNode struct {
	cfg    NodeConfig
	pq     PQKey
	rsaKey *rsa.PrivateKey
	sm2Key *sm2.PrivateKey
	sm2Pub *sm2.PublicKey
	native *x509.Certificate
	gm     *gx.Certificate
	der    []byte
}

func generate(c Config) (Report, error) {
	var empty Report
	if _, err := os.Lstat(c.OutputDir); !os.IsNotExist(err) {
		return empty, fmt.Errorf("输出目录已存在或不可访问，拒绝覆盖: %s", c.OutputDir)
	}
	parentDir := filepath.Dir(c.OutputDir)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		return empty, err
	}
	work, err := os.MkdirTemp(parentDir, ".pqc-certtool-")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(work)
	now := time.Now().UTC().Truncate(time.Second)
	var parent *generatedNode
	for i, n := range append([]NodeConfig{c.Root}, c.Intermediates...) {
		child, err := createNode(c.Mode, n, parent, true, len(c.Intermediates)-i, now)
		if err != nil {
			return empty, fmt.Errorf("生成%s失败: %w", n.Name, err)
		}
		if err = writeNode(work, c.Mode, child); err != nil {
			return empty, err
		}
		parent = child
	}
	for _, n := range c.Leaves {
		child, err := createNode(c.Mode, n, parent, false, -1, now)
		if err != nil {
			return empty, fmt.Errorf("生成%s失败: %w", n.Name, err)
		}
		if err = writeNode(work, c.Mode, child); err != nil {
			return empty, err
		}
	}
	report, err := verify(c, work)
	if err != nil {
		return empty, fmt.Errorf("生成后验签失败: %w", err)
	}
	report.OutputDir = c.OutputDir
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return empty, err
	}
	if err = os.WriteFile(filepath.Join(work, "report.json"), append(data, '\n'), 0644); err != nil {
		return empty, err
	}
	// NOREPLACE also protects against concurrent generation into the same path.
	if err = unix.Renameat2(unix.AT_FDCWD, work, unix.AT_FDCWD, c.OutputDir, unix.RENAME_NOREPLACE); err != nil {
		return empty, fmt.Errorf("发布输出失败，未覆盖现有目录: %w", err)
	}
	return report, nil
}
func createNode(mode string, n NodeConfig, parent *generatedNode, ca bool, pathLen int, now time.Time) (*generatedNode, error) {
	g := &generatedNode{cfg: n}
	var err error
	if mode != "sm2" {
		g.pq, err = makePQKey(n)
		if err != nil {
			return nil, err
		}
	}
	switch mode {
	case "rsa-hybrid":
		g.rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case "sm2-hybrid":
		g.sm2Pub, g.sm2Key, err = makeSM2Key(NodeConfig{})
	case "sm2":
		g.sm2Pub, g.sm2Key, err = makeSM2Key(n)
	}
	if err != nil {
		return nil, err
	}
	if parent == nil {
		parent = g
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	start, end := now.Add(-5*time.Minute), now.AddDate(0, 0, n.ValidDays)
	if mode == "pure-pq" {
		a, _ := algorithm(n.Algorithm)
		issuerAlgo, _ := algorithm(parent.cfg.Algorithm)
		subject, err := dn(n.CommonName)
		if err != nil {
			return nil, err
		}
		issuer, err := dn(parent.cfg.CommonName)
		if err != nil {
			return nil, err
		}
		bc, err := asDER(Constraints{ca, pathLen})
		if err != nil {
			return nil, err
		}
		usage := asn1.BitString{Bytes: []byte{0x80}, BitLength: 1}
		if ca {
			usage = asn1.BitString{Bytes: []byte{0x06}, BitLength: 7}
		} else if a.KEM != nil {
			usage = asn1.BitString{Bytes: []byte{0x20}, BitLength: 3}
		}
		ku, err := asDER(usage)
		if err != nil {
			return nil, err
		}
		t := TBS{Version: 2, SerialNumber: sn, Signature: AlgorithmID{Algorithm: issuerAlgo.OID}, Issuer: issuer, Subject: subject, Validity: Validity{start, end}, PublicKey: PublicKeyInfo{AlgorithmID{Algorithm: a.OID}, asn1.BitString{Bytes: g.pq.Public, BitLength: 8 * len(g.pq.Public)}}, Extensions: []pkix.Extension{{Id: oidBasic, Critical: true, Value: bc}, {Id: oidKeyUsage, Critical: true, Value: ku}}}
		raw, err := asDER(t)
		if err != nil {
			return nil, err
		}
		sig := issuerAlgo.Sign.Sign(parent.pq.Signer, raw, nil)
		g.der, err = asDER(Certificate{t, AlgorithmID{Algorithm: issuerAlgo.OID}, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
		if err != nil {
			return nil, err
		}
		return g, nil
	}
	var exts []pkix.Extension
	if mode != "sm2" {
		a, _ := algorithm(n.Algorithm)
		value, err := pqValue(a, g.pq.Public)
		if err != nil {
			return nil, err
		}
		exts = []pkix.Extension{{Id: oidPQPublic, Value: value}}
	}
	if mode == "rsa-hybrid" {
		usage := x509.KeyUsageDigitalSignature
		if ca {
			usage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}
		tpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: n.CommonName}, NotBefore: start, NotAfter: end, IsCA: ca, BasicConstraintsValid: true, MaxPathLen: pathLen, MaxPathLenZero: ca && pathLen == 0, KeyUsage: usage, SignatureAlgorithm: x509.SHA256WithRSA, ExtraExtensions: exts}
		issuer := parent.native
		if parent == g {
			issuer = tpl
		}
		g.der, err = x509.CreateCertificate(rand.Reader, tpl, issuer, &g.rsaKey.PublicKey, parent.rsaKey)
		if err != nil {
			return nil, err
		}
		initial, err := parseDER(g.der)
		if err != nil {
			return nil, err
		}
		a, _ := algorithm(parent.cfg.Algorithm)
		sig := a.Sign.Sign(parent.pq.Signer, initial.TBS.Raw, nil)
		value, err := pqValue(a, sig)
		if err != nil {
			return nil, err
		}
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: oidPQSignature, Value: value})
		g.der, err = x509.CreateCertificate(rand.Reader, tpl, issuer, &g.rsaKey.PublicKey, parent.rsaKey)
		if err != nil {
			return nil, err
		}
		g.native, err = x509.ParseCertificate(g.der)
	} else {
		usage := gx.KeyUsageDigitalSignature
		if ca {
			usage = gx.KeyUsageCertSign | gx.KeyUsageCRLSign
		}
		tpl := &gx.Certificate{Version: 3, SerialNumber: sn, Subject: pkix.Name{CommonName: n.CommonName}, NotBefore: start, NotAfter: end, IsCA: ca, BasicConstraintsValid: true, MaxPathLen: pathLen, MaxPathLenZero: ca && pathLen == 0, KeyUsage: usage, SignatureAlgorithm: gx.SM2WithSM3, ExtraExtensions: exts}
		issuer := parent.gm
		if parent == g {
			issuer = tpl
		}
		g.der, err = gx.CreateCertificate(tpl, issuer, g.sm2Pub, parent.sm2Key)
		if err != nil {
			return nil, err
		}
		if mode == "sm2-hybrid" {
			initial, err := parseDER(g.der)
			if err != nil {
				return nil, err
			}
			a, _ := algorithm(parent.cfg.Algorithm)
			sig := a.Sign.Sign(parent.pq.Signer, initial.TBS.Raw, nil)
			value, err := pqValue(a, sig)
			if err != nil {
				return nil, err
			}
			tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: oidPQSignature, Value: value})
			g.der, err = gx.CreateCertificate(tpl, issuer, g.sm2Pub, parent.sm2Key)
			if err != nil {
				return nil, err
			}
		}
		g.gm, err = gx.ParseCertificate(g.der)
	}
	return g, err
}
func writePEM(path, kind string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}), mode)
}
func writeNode(dir, mode string, g *generatedNode) error {
	base := filepath.Join(dir, g.cfg.Name)
	if err := writePEM(base+".crt", "CERTIFICATE", g.der, 0644); err != nil {
		return err
	}
	if mode != "sm2" {
		pub := pem.EncodeToMemory(&pem.Block{Type: "PQC PUBLIC KEY", Headers: map[string]string{"Algorithm": canonicalName(g.cfg.Algorithm)}, Bytes: g.pq.Public})
		if err := os.WriteFile(base+".pub", pub, 0644); err != nil {
			return err
		}
		if len(g.pq.Private) > 0 {
			suffix := ".key"
			if mode != "pure-pq" {
				suffix = ".pq.key"
			}
			if err := writePEM(base+suffix, "PQC PRIVATE KEY", g.pq.Private, 0600); err != nil {
				return err
			}
		}
	}
	if mode == "rsa-hybrid" {
		raw, err := x509.MarshalPKCS8PrivateKey(g.rsaKey)
		if err != nil {
			return err
		}
		if err = writePEM(base+".key", "PRIVATE KEY", raw, 0600); err != nil {
			return err
		}
		pub, err := x509.MarshalPKIXPublicKey(&g.rsaKey.PublicKey)
		if err != nil {
			return err
		}
		return writePEM(base+".classic.pub", "PUBLIC KEY", pub, 0644)
	}
	if mode == "sm2" || mode == "sm2-hybrid" {
		if g.sm2Key != nil {
			raw, err := gx.MarshalSm2UnecryptedPrivateKey(g.sm2Key)
			if err != nil {
				return err
			}
			if err = writePEM(base+".key", "PRIVATE KEY", raw, 0600); err != nil {
				return err
			}
		}
		pub, err := gx.MarshalSm2PublicKey(g.sm2Pub)
		if err != nil {
			return err
		}
		suffix := ".pub"
		if mode == "sm2-hybrid" {
			suffix = ".classic.pub"
		}
		return writePEM(base+suffix, "PUBLIC KEY", pub, 0644)
	}
	return nil
}
