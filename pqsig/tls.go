package pqsig

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Private TLS 1.3 SignatureScheme values reserved for this project. 0xFE01 is
// the existing Dilithium2 value in go_kemtls; the rest are kept in the same
// private range and must be mirrored in the patched crypto/tls package.
const (
	TLSDilithium2 uint16 = 0xFE01
	TLSDilithium3 uint16 = 0xFE02
	TLSDilithium5 uint16 = 0xFE03

	TLSSLHDSASHA2_128s uint16 = 0xFE10
	TLSSLHDSASHA2_128f uint16 = 0xFE11
	TLSSLHDSASHA2_192s uint16 = 0xFE12
	TLSSLHDSASHA2_192f uint16 = 0xFE13
	TLSSLHDSASHA2_256s uint16 = 0xFE14
	TLSSLHDSASHA2_256f uint16 = 0xFE15
)

var tlsCodeByName = map[string]uint16{
	"Dilithium2":        TLSDilithium2,
	"Dilithium3":        TLSDilithium3,
	"Dilithium5":        TLSDilithium5,
	"SLH-DSA-SHA2-128s": TLSSLHDSASHA2_128s,
	"SLH-DSA-SHA2-128f": TLSSLHDSASHA2_128f,
	"SLH-DSA-SHA2-192s": TLSSLHDSASHA2_192s,
	"SLH-DSA-SHA2-192f": TLSSLHDSASHA2_192f,
	"SLH-DSA-SHA2-256s": TLSSLHDSASHA2_256s,
	"SLH-DSA-SHA2-256f": TLSSLHDSASHA2_256f,
}

var tlsCodeToName = func() map[uint16]string {
	m := make(map[uint16]string, len(tlsCodeByName))
	for name, code := range tlsCodeByName {
		if _, ok := m[code]; ok {
			panic("pqsig: duplicate TLS signature code")
		}
		m[code] = name
	}
	return m
}()

// TLSCode returns the private TLS SignatureScheme for an algorithm.
func TLSCode(alg Algorithm) (uint16, bool) {
	if alg == nil {
		return 0, false
	}
	code, ok := tlsCodeByName[alg.Name()]
	return code, ok
}

// AlgorithmByTLSCode resolves a private TLS SignatureScheme to the algorithm.
func AlgorithmByTLSCode(code uint16) (Algorithm, bool) {
	name, ok := tlsCodeToName[code]
	if !ok {
		return nil, false
	}
	return ByName(name)
}

// CertificateVerifyInput builds the TLS 1.3 signed content:
//
//	64 bytes of 0x20 || context || 0x00 || transcript hash
//
// This is the input a TLS CertificateVerify implementation must sign for the
// selected signature algorithm.
func CertificateVerifyInput(context string, transcript []byte) []byte {
	var b bytes.Buffer
	b.Write(bytes.Repeat([]byte{0x20}, 64))
	b.WriteString(context)
	b.WriteByte(0)
	b.Write(transcript)
	return b.Bytes()
}

// TLSName returns a display name including the private SignatureScheme value.
func TLSName(alg Algorithm) string {
	code, ok := TLSCode(alg)
	if !ok {
		return alg.Name()
	}
	return fmt.Sprintf("%s(0x%04x)", alg.Name(), code)
}

// AppendUint16 is a small helper for callers that encode the private code in a
// handshake structure. It keeps the wire format explicit at call sites.
func AppendUint16(dst []byte, v uint16) []byte {
	return binary.BigEndian.AppendUint16(dst, v)
}
