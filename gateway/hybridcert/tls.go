package hybridcert

import (
	"crypto"
	"crypto/tls"
	"errors"
	"io"
	"time"

	"pqc-gateway/hybridsig"
)

// TLSSigner signs a TLS 1.3 CertificateVerify input with both identity keys.
type TLSSigner struct {
	Identity *Identity
	Level    hybridsig.Level
}

func Scheme(level hybridsig.Level) (tls.SignatureScheme, error) {
	switch level {
	case hybridsig.Level128:
		return tls.SM2WithMLDSA44, nil
	case hybridsig.Level256:
		return tls.SM2WithMLDSA87, nil
	default:
		return 0, errors.New("unsupported hybrid authentication level")
	}
}

func (s *TLSSigner) TLSHybridSignatureScheme() tls.SignatureScheme {
	scheme, _ := Scheme(s.Level)
	return scheme
}

func (s *TLSSigner) Public() crypto.PublicKey { return s.Identity.SM2Public }

func (s *TLSSigner) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != 0 {
		return nil, errors.New("hybrid TLS signature requires the original CertificateVerify input")
	}
	return hybridsig.Sign(s.Level, s.Identity.SM2Private, s.Identity.PQPrivate, message)
}

// ServerCertificate loads the local server identity and returns its TLS wire chain.
func ServerCertificate(rootPath string, intermediatePaths []string, leafPath, sm2KeyPath, pqKeyPath string, level hybridsig.Level, serverName string) (tls.Certificate, error) {
	return tlsCertificate(rootPath, intermediatePaths, leafPath, sm2KeyPath, pqKeyPath, level, Server, serverName)
}

// ClientCertificate loads the local client identity for mutual TLS.
func ClientCertificate(rootPath string, intermediatePaths []string, leafPath, sm2KeyPath, pqKeyPath string, level hybridsig.Level) (tls.Certificate, error) {
	return tlsCertificate(rootPath, intermediatePaths, leafPath, sm2KeyPath, pqKeyPath, level, Client, "")
}

func tlsCertificate(rootPath string, intermediatePaths []string, leafPath, sm2KeyPath, pqKeyPath string, level hybridsig.Level, purpose Purpose, serverName string) (tls.Certificate, error) {
	id, err := LoadChain(rootPath, intermediatePaths, leafPath, sm2KeyPath, pqKeyPath, level, purpose, serverName, time.Now())
	if err != nil {
		return tls.Certificate{}, err
	}
	chain := [][]byte{id.LeafDER}
	for i := len(intermediatePaths) - 1; i >= 0; i-- {
		der, err := readPEM(intermediatePaths[i], "CERTIFICATE")
		if err != nil {
			return tls.Certificate{}, err
		}
		chain = append(chain, der)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: &TLSSigner{Identity: id, Level: level}}, nil
}

// NewClientVerifier pins the trusted client CA for mutual TLS.
func NewClientVerifier(rootPath string, level hybridsig.Level) (func([][]byte, []byte, []byte) error, error) {
	if _, err := Scheme(level); err != nil {
		return nil, err
	}
	rootDER, err := readPEM(rootPath, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	if err := ValidateTrustRoot(rootDER, level, time.Now()); err != nil {
		return nil, err
	}
	return func(chain [][]byte, signed, signature []byte) error {
		id, err := VerifyDERChain(rootDER, chain, level, Client, "", time.Now())
		if err != nil {
			return err
		}
		return hybridsig.Verify(level, id.SM2Public, id.PQPublic, signed, signature)
	}, nil
}

// NewServerVerifier pins the trusted root and verifies each peer's certificate
// chain and CertificateVerify signature with both SM2 and ML-DSA.
func NewServerVerifier(rootPath string, level hybridsig.Level) (func([][]byte, string, []byte, []byte) error, error) {
	if _, err := Scheme(level); err != nil {
		return nil, err
	}
	rootDER, err := readPEM(rootPath, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	if err := ValidateTrustRoot(rootDER, level, time.Now()); err != nil {
		return nil, err
	}
	return func(chain [][]byte, serverName string, signed, signature []byte) error {
		id, err := VerifyDERChain(rootDER, chain, level, Server, serverName, time.Now())
		if err != nil {
			return err
		}
		return hybridsig.Verify(level, id.SM2Public, id.PQPublic, signed, signature)
	}, nil
}
