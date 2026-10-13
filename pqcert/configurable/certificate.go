package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

type AlgorithmID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}
type PublicKeyInfo struct {
	Algorithm AlgorithmID
	PublicKey asn1.BitString
}
type Validity struct{ NotBefore, NotAfter time.Time }
type TBS struct {
	Raw             asn1.RawContent
	Version         int `asn1:"optional,explicit,tag:0"`
	SerialNumber    *big.Int
	Signature       AlgorithmID
	Issuer          asn1.RawValue
	Validity        Validity
	Subject         asn1.RawValue
	PublicKey       PublicKeyInfo
	IssuerUniqueID  asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID asn1.BitString   `asn1:"optional,tag:2"`
	Extensions      []pkix.Extension `asn1:"optional,explicit,tag:3"`
}
type Certificate struct {
	TBS                TBS
	SignatureAlgorithm AlgorithmID
	Signature          asn1.BitString
}
type Constraints struct {
	CA      bool `asn1:"optional"`
	PathLen int  `asn1:"optional,default:-1"`
}
type PQExtension struct {
	Algorithm asn1.ObjectIdentifier
	Data      []byte
}

var oidBasic = asn1.ObjectIdentifier{2, 5, 29, 19}
var oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}
var oidPQPublic = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 1}
var oidPQSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 2}

func parseDER(data []byte) (*Certificate, error) {
	var c Certificate
	rest, err := asn1.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("证书尾部有多余数据")
	}
	if c.TBS.SerialNumber == nil || c.TBS.SerialNumber.Sign() <= 0 || c.TBS.Version != 2 {
		return nil, fmt.Errorf("证书版本或序列号无效")
	}
	if c.Signature.BitLength != 8*len(c.Signature.Bytes) || c.TBS.PublicKey.PublicKey.BitLength != 8*len(c.TBS.PublicKey.PublicKey.Bytes) {
		return nil, fmt.Errorf("证书位串无效")
	}
	if !c.SignatureAlgorithm.Algorithm.Equal(c.TBS.Signature.Algorithm) {
		return nil, fmt.Errorf("签名算法不一致")
	}
	seen := map[string]bool{}
	for _, e := range c.TBS.Extensions {
		if seen[e.Id.String()] {
			return nil, fmt.Errorf("重复证书扩展")
		}
		seen[e.Id.String()] = true
	}
	return &c, nil
}
func asDER(v any) ([]byte, error) { return asn1.Marshal(v) }
func serial() (*big.Int, error) {
	for {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil || n.Sign() > 0 {
			return n, err
		}
	}
}
func dn(cn string) (asn1.RawValue, error) {
	b, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
	return asn1.RawValue{FullBytes: b}, err
}
func commonName(raw []byte) (string, error) {
	var r pkix.RDNSequence
	rest, err := asn1.Unmarshal(raw, &r)
	if err != nil || len(rest) != 0 {
		return "", fmt.Errorf("无效证书名称")
	}
	var n pkix.Name
	n.FillFromRDNSequence(&r)
	return n.CommonName, nil
}
func pqValue(a Algorithm, data []byte) ([]byte, error) { return asDER(PQExtension{a.OID, data}) }
func getPQ(c *Certificate, oid asn1.ObjectIdentifier) (PQExtension, error) {
	for _, e := range c.TBS.Extensions {
		if e.Id.Equal(oid) {
			var p PQExtension
			rest, err := asn1.Unmarshal(e.Value, &p)
			if err != nil || len(rest) != 0 {
				return p, fmt.Errorf("无效PQ扩展")
			}
			return p, nil
		}
	}
	return PQExtension{}, fmt.Errorf("缺少PQ扩展: %s", oid)
}
func unsignedPQTBS(c *Certificate) ([]byte, error) {
	t := c.TBS
	t.Raw = nil
	t.Extensions = nil
	for _, e := range c.TBS.Extensions {
		if !e.Id.Equal(oidPQSignature) {
			t.Extensions = append(t.Extensions, e)
		}
	}
	return asDER(t)
}
