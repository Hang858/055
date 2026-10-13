// Package hybridsig signs the same TLS authentication input with SM2 and ML-DSA.
// A valid result requires both signatures. TLS negotiation and certificate
// validation are handled separately by the handshake layer.
package hybridsig

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/tjfoc/gmsm/sm2"
)

// Level identifies the two quantum security categories required by the TLS profile.
type Level uint16

const (
	Level128 Level = 128
	Level256 Level = 256
)

type sm2Signature struct{ R, S *big.Int }

func schemeFor(level Level) (sign.Scheme, error) {
	switch level {
	case Level128:
		return mldsa44.Scheme(), nil
	case Level256:
		return mldsa87.Scheme(), nil
	default:
		return nil, fmt.Errorf("unsupported hybrid signature level: %d", level)
	}
}

// Sign returns a DER-encoded SM2 signature followed by a fixed-size ML-DSA
// signature. Both cover the identical message supplied by the TLS layer.
func Sign(level Level, classical *sm2.PrivateKey, pq sign.PrivateKey, message []byte) ([]byte, error) {
	scheme, err := schemeFor(level)
	if err != nil {
		return nil, err
	}
	if classical == nil || pq == nil || pq.Scheme().Name() != scheme.Name() {
		return nil, errors.New("hybrid signature key does not match profile")
	}
	r, s, err := sm2.Sm2Sign(classical, message, nil, rand.Reader)
	if err != nil {
		return nil, err
	}
	classicalSignature, err := asn1.Marshal(sm2Signature{r, s})
	if err != nil {
		return nil, err
	}
	pqSignature := scheme.Sign(pq, message, nil)
	return append(classicalSignature, pqSignature...), nil
}

// Verify rejects the result unless the SM2 and ML-DSA signatures both verify.
func Verify(level Level, classical *sm2.PublicKey, pq sign.PublicKey, message, signature []byte) error {
	scheme, err := schemeFor(level)
	if err != nil {
		return err
	}
	if classical == nil || pq == nil || pq.Scheme().Name() != scheme.Name() {
		return errors.New("hybrid verification key does not match profile")
	}
	if len(signature) < 8+scheme.SignatureSize() || len(signature) > 128+scheme.SignatureSize() {
		return errors.New("invalid hybrid signature length")
	}
	var classicalSignature sm2Signature
	rest, err := asn1.Unmarshal(signature, &classicalSignature)
	if err != nil || classicalSignature.R == nil || classicalSignature.S == nil || len(rest) != scheme.SignatureSize() {
		return errors.New("invalid SM2 or ML-DSA signature encoding")
	}
	if !sm2.Sm2Verify(classical, message, nil, classicalSignature.R, classicalSignature.S) {
		return errors.New("SM2 signature verification failed")
	}
	if !scheme.Verify(pq, message, rest, nil) {
		return errors.New("ML-DSA signature verification failed")
	}
	return nil
}
