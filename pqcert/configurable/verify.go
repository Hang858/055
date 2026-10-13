package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	gx "github.com/tjfoc/gmsm/x509"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"
)

type NodeResult struct {
	Name              string `json:"name"`
	CommonName        string `json:"common_name"`
	Issuer            string `json:"issuer"`
	Algorithm         string `json:"algorithm"`
	CA                bool   `json:"ca"`
	CertificateSHA256 string `json:"certificate_sha256"`
}
type Report struct {
	Verified     bool         `json:"verified"`
	Mode         string       `json:"mode"`
	OutputDir    string       `json:"output_dir"`
	Certificates []NodeResult `json:"certificates"`
}

func readCertificate(path string) (*Certificate, []byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return nil, nil, fmt.Errorf("证书必须为不超过1 MiB的普通文件")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	b, rest := pem.Decode(data)
	if b == nil || b.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, fmt.Errorf("无效CERTIFICATE PEM")
	}
	c, err := parseDER(b.Bytes)
	return c, b.Bytes, err
}
func verify(cfg Config, dir string) (Report, error) {
	r := Report{Mode: cfg.Mode, OutputDir: dir}
	var parent *Certificate
	var parentDER []byte
	var parentCfg NodeConfig
	verifyNode := func(n NodeConfig, ca bool, pathLen int) error {
		c, der, err := readCertificate(filepath.Join(dir, n.Name+".crt"))
		if err != nil {
			return fmt.Errorf("%s: %w", n.Name, err)
		}
		issuer, issuerDER, issuerCfg := parent, parentDER, parentCfg
		if issuer == nil {
			issuer, issuerDER, issuerCfg = c, der, n
		}
		if err = checkCertificate(cfg.Mode, n, ca, pathLen, c, der, issuer, issuerDER, issuerCfg, time.Now()); err != nil {
			return fmt.Errorf("%s: %w", n.Name, err)
		}
		hash := sha256.Sum256(der)
		r.Certificates = append(r.Certificates, NodeResult{n.Name, n.CommonName, issuerCfg.CommonName, canonicalName(n.Algorithm), ca, hex.EncodeToString(hash[:])})
		if ca {
			parent, parentDER, parentCfg = c, der, n
		}
		return nil
	}
	for i, n := range append([]NodeConfig{cfg.Root}, cfg.Intermediates...) {
		if err := verifyNode(n, true, len(cfg.Intermediates)-i); err != nil {
			return r, err
		}
	}
	for _, n := range cfg.Leaves {
		if err := verifyNode(n, false, -1); err != nil {
			return r, err
		}
	}
	r.Verified = true
	return r, nil
}
func checkCertificate(mode string, n NodeConfig, ca bool, pathLen int, c *Certificate, der []byte, parent *Certificate, parentDER []byte, parentCfg NodeConfig, now time.Time) error {
	cn, err := commonName(c.TBS.Subject.FullBytes)
	if err != nil || cn != n.CommonName {
		return fmt.Errorf("证书名称与配置不一致")
	}
	if !bytes.Equal(c.TBS.Issuer.FullBytes, parent.TBS.Subject.FullBytes) {
		return fmt.Errorf("签发关系不匹配")
	}
	if now.Before(c.TBS.Validity.NotBefore) || !now.Before(c.TBS.Validity.NotAfter) {
		return fmt.Errorf("证书尚未生效或已过期")
	}
	if c.TBS.Validity.NotAfter.Sub(c.TBS.Validity.NotBefore) != time.Duration(n.ValidDays)*24*time.Hour+5*time.Minute {
		return fmt.Errorf("有效期与配置不一致")
	}
	if c.TBS.Validity.NotBefore.Before(parent.TBS.Validity.NotBefore) || c.TBS.Validity.NotAfter.After(parent.TBS.Validity.NotAfter) {
		return fmt.Errorf("证书有效期超出签发者")
	}
	foundBC, foundKU := false, false
	for _, e := range c.TBS.Extensions {
		if e.Id.Equal(oidBasic) {
			var bc Constraints
			rest, err := asn1.Unmarshal(e.Value, &bc)
			if err != nil || len(rest) != 0 || bc.CA != ca || bc.PathLen != pathLen {
				return fmt.Errorf("CA约束与配置不一致")
			}
			foundBC = true
		}
		if e.Id.Equal(oidKeyUsage) {
			var ku asn1.BitString
			rest, err := asn1.Unmarshal(e.Value, &ku)
			if err != nil || len(rest) != 0 {
				return fmt.Errorf("用途扩展无效")
			}
			bit := 0
			if ca {
				bit = 5
			} else if mode == "pure-pq" {
				a, _ := algorithm(n.Algorithm)
				if a.KEM != nil {
					bit = 2
				}
			}
			if ku.At(bit) != 1 {
				return fmt.Errorf("证书用途不匹配")
			}
			foundKU = true
		}
		if e.Critical && !e.Id.Equal(oidBasic) && !e.Id.Equal(oidKeyUsage) {
			return fmt.Errorf("不支持的关键扩展: %s", e.Id)
		}
	}
	if !foundBC || !foundKU {
		return fmt.Errorf("缺少CA或用途扩展")
	}
	var public []byte
	if mode == "pure-pq" {
		a, _ := algorithm(n.Algorithm)
		issuer, _ := algorithm(parentCfg.Algorithm)
		if !c.TBS.PublicKey.Algorithm.Algorithm.Equal(a.OID) || !c.SignatureAlgorithm.Algorithm.Equal(issuer.OID) {
			return fmt.Errorf("证书算法与配置不一致")
		}
		pk, err := issuer.Sign.UnmarshalBinaryPublicKey(parent.TBS.PublicKey.PublicKey.Bytes)
		if err != nil {
			return err
		}
		if !issuer.Sign.Verify(pk, c.TBS.Raw, c.Signature.Bytes, nil) {
			return fmt.Errorf("抗量子签名验证失败")
		}
		public = c.TBS.PublicKey.PublicKey.Bytes
	} else {
		if mode == "rsa-hybrid" {
			native, err := x509.ParseCertificate(der)
			if err != nil {
				return err
			}
			issuer, err := x509.ParseCertificate(parentDER)
			if err != nil {
				return err
			}
			if _, ok := native.PublicKey.(*rsa.PublicKey); !ok || native.SignatureAlgorithm != x509.SHA256WithRSA {
				return fmt.Errorf("主证书必须使用RSA/SHA256")
			}
			if err = native.CheckSignatureFrom(issuer); err != nil {
				return fmt.Errorf("RSA签名验证失败: %w", err)
			}
		} else {
			native, err := gx.ParseCertificate(der)
			if err != nil {
				return err
			}
			issuer, err := gx.ParseCertificate(parentDER)
			if err != nil {
				return err
			}
			subject, ok := native.PublicKey.(*ecdsa.PublicKey)
			if !ok || subject.Curve != sm2.P256Sm2() || !validSM2Point(subject.X, subject.Y) {
				return fmt.Errorf("主体公钥必须使用SM2曲线")
			}
			if native.SignatureAlgorithm != gx.SM2WithSM3 {
				return fmt.Errorf("主证书必须使用SM2/SM3")
			}
			if err = native.CheckSignatureFrom(issuer); err != nil {
				return fmt.Errorf("SM2签名验证失败: %w", err)
			}
		}
		if mode != "sm2" {
			a, _ := algorithm(n.Algorithm)
			issuer, _ := algorithm(parentCfg.Algorithm)
			pub, err := getPQ(c, oidPQPublic)
			if err != nil {
				return err
			}
			if !pub.Algorithm.Equal(a.OID) {
				return fmt.Errorf("PQ公钥算法不匹配")
			}
			ipub, err := getPQ(parent, oidPQPublic)
			if err != nil {
				return err
			}
			if !ipub.Algorithm.Equal(issuer.OID) {
				return fmt.Errorf("签发者PQ公钥算法不匹配")
			}
			sig, err := getPQ(c, oidPQSignature)
			if err != nil {
				return err
			}
			if !sig.Algorithm.Equal(issuer.OID) {
				return fmt.Errorf("PQ签名算法不匹配")
			}
			pk, err := issuer.Sign.UnmarshalBinaryPublicKey(ipub.Data)
			if err != nil {
				return err
			}
			raw, err := unsignedPQTBS(c)
			if err != nil {
				return err
			}
			if !issuer.Sign.Verify(pk, raw, sig.Data, nil) {
				return fmt.Errorf("抗量子扩展签名验证失败")
			}
			public = pub.Data
		} else {
			public, err = asDER(c.TBS.PublicKey)
			if err != nil {
				return err
			}
		}
	}
	if mode != "sm2" {
		a, _ := algorithm(n.Algorithm)
		if a.Sign != nil {
			_, err = a.Sign.UnmarshalBinaryPublicKey(public)
		} else {
			_, err = a.KEM.UnmarshalBinaryPublicKey(public)
		}
		if err != nil {
			return fmt.Errorf("用户公钥无效: %w", err)
		}
	}
	if n.PublicKeyFile != "" {
		expected, err := importPublic(n.Algorithm, n.PublicKeyFile)
		if err != nil {
			return err
		}
		if !bytes.Equal(expected, public) {
			return fmt.Errorf("证书公钥与导入文件不一致")
		}
	}
	if n.TLSUsage != "" {
		parsed, err := gx.ParseCertificate(der)
		if err != nil {
			return err
		}
		if !slices.Equal(parsed.DNSNames, n.DNSNames) || len(parsed.IPAddresses) != len(n.IPAddresses) {
			return fmt.Errorf("TLS SAN与配置不一致")
		}
		for i, text := range n.IPAddresses {
			if !parsed.IPAddresses[i].Equal(net.ParseIP(text)) {
				return fmt.Errorf("TLS IP SAN与配置不一致")
			}
		}
		usage := gx.ExtKeyUsageServerAuth
		if n.TLSUsage == "client" {
			usage = gx.ExtKeyUsageClientAuth
		}
		if len(parsed.ExtKeyUsage) != 1 || parsed.ExtKeyUsage[0] != usage {
			return fmt.Errorf("TLS证书用途与配置不一致")
		}
	}
	return nil
}
