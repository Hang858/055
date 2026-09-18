package hybrid

// TODO move over to crypto/ecdh once we can assume Go 1.20.

import (
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"crypto/rand"
	"crypto/subtle"
	"math/big"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/xof"
	"github.com/cloudflare/circl/internal/sha3"
	"github.com/tjfoc/gmsm/sm2" 
)

type cPublicKey struct {
	scheme *cScheme
	x, y   *big.Int
}
type cPrivateKey struct {
	scheme *cScheme
	key    []byte
}
type cScheme struct {
	curve elliptic.Curve
}

var p256Kem = &cScheme{elliptic.P256()}

func (sch *cScheme) scSize() int {
	return (sch.curve.Params().N.BitLen() + 7) / 8
}

func (sch *cScheme) ptSize() int {
	return (sch.curve.Params().BitSize + 7) / 8
}

func (sch *cScheme) Name() string {
	return sch.curve.Params().Name
}

func (sch *cScheme) PublicKeySize() int {
	return 2*sch.ptSize() + 1
}

func (sch *cScheme) PrivateKeySize() int {
	return sch.scSize()
}

func (sch *cScheme) SeedSize() int {
	return sch.PrivateKeySize()
}

func (sch *cScheme) SharedKeySize() int {
	return sch.ptSize()
}

func (sch *cScheme) CiphertextSize() int {
	return sch.PublicKeySize()
}

func (sch *cScheme) EncapsulationSeedSize() int {
	return sch.SeedSize()
}

func (sk *cPrivateKey) Scheme() kem.Scheme { return sk.scheme }
func (pk *cPublicKey) Scheme() kem.Scheme  { return pk.scheme }

func (sk *cPrivateKey) MarshalBinary() ([]byte, error) {
	ret := make([]byte, len(sk.key))
	copy(ret, sk.key)
	return ret, nil
}

func (sk *cPrivateKey) Equal(other kem.PrivateKey) bool {
	oth, ok := other.(*cPrivateKey)
	if !ok {
		return false
	}
	if oth.scheme != sk.scheme {
		return false
	}
	return subtle.ConstantTimeCompare(oth.key, sk.key) == 1
}

func (sk *cPrivateKey) Public() kem.PublicKey {
	x, y := sk.scheme.curve.ScalarBaseMult(sk.key)
	return &cPublicKey{
		sk.scheme,
		x,
		y,
	}
}

func (pk *cPublicKey) Equal(other kem.PublicKey) bool {
	oth, ok := other.(*cPublicKey)
	if !ok {
		return false
	}
	if oth.scheme != pk.scheme {
		return false
	}
	return oth.x.Cmp(pk.x) == 0 && oth.y.Cmp(pk.y) == 0
}

func (pk *cPublicKey) MarshalBinary() ([]byte, error) {
	return elliptic.Marshal(pk.scheme.curve, pk.x, pk.y), nil
}

func (sch *cScheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	seed := make([]byte, sch.SeedSize())
	_, err := cryptoRand.Read(seed)
	if err != nil {
		return nil, nil, err
	}
	pk, sk := sch.DeriveKeyPair(seed)
	return pk, sk, nil
}

func (sch *cScheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != sch.SeedSize() {
		panic(kem.ErrSeedSize)
	}
	h := xof.SHAKE256.New()
	_, _ = h.Write(seed)
	key, x, y, err := elliptic.GenerateKey(sch.curve, h)
	if err != nil {
		panic(err)
	}

	sk := cPrivateKey{scheme: sch, key: key}
	pk := cPublicKey{scheme: sch, x: x, y: y}

	return &pk, &sk
}

func (sch *cScheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	seed := make([]byte, sch.EncapsulationSeedSize())
	_, err = cryptoRand.Read(seed)
	if err != nil {
		return
	}
	return sch.EncapsulateDeterministically(pk, seed)
}

func (pk *cPublicKey) X(sk *cPrivateKey) []byte {
	if pk.scheme != sk.scheme {
		panic(kem.ErrTypeMismatch)
	}

	sharedKey := make([]byte, pk.scheme.SharedKeySize())
	xShared, _ := pk.scheme.curve.ScalarMult(pk.x, pk.y, sk.key)
	xShared.FillBytes(sharedKey)
	return sharedKey
}

func (sch *cScheme) EncapsulateDeterministically(
	pk kem.PublicKey, seed []byte,
) (ct, ss []byte, err error) {
	if len(seed) != sch.EncapsulationSeedSize() {
		return nil, nil, kem.ErrSeedSize
	}
	pub, ok := pk.(*cPublicKey)
	if !ok || pub.scheme != sch {
		return nil, nil, kem.ErrTypeMismatch
	}

	pk2, sk2 := sch.DeriveKeyPair(seed)
	ss = pub.X(sk2.(*cPrivateKey))
	ct, _ = pk2.MarshalBinary()
	return
}

func (sch *cScheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != sch.CiphertextSize() {
		return nil, kem.ErrCiphertextSize
	}

	priv, ok := sk.(*cPrivateKey)
	if !ok || priv.scheme != sch {
		return nil, kem.ErrTypeMismatch
	}

	pk, err := sch.UnmarshalBinaryPublicKey(ct)
	if err != nil {
		return nil, err
	}

	ss := pk.(*cPublicKey).X(priv)
	return ss, nil
}

func (sch *cScheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	if len(buf) != sch.PublicKeySize() {
		return nil, kem.ErrPubKeySize
	}
	x, y := elliptic.Unmarshal(sch.curve, buf)
	return &cPublicKey{sch, x, y}, nil
}

func (sch *cScheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	if len(buf) != sch.PrivateKeySize() {
		return nil, kem.ErrPrivKeySize
	}
	ret := cPrivateKey{sch, make([]byte, sch.PrivateKeySize())}
	copy(ret.key, buf)
	return &ret, nil
}


//添加sm2部分 write by drew
// SM2 KEM 方案
type sm2PublicKey struct {
    scheme *sm2Scheme
    x, y   *big.Int
}

type sm2PrivateKey struct {
    scheme *sm2Scheme
    key    []byte
}

type sm2Scheme struct {
    curve elliptic.Curve
}

var sm2Kem = &sm2Scheme{sm2.P256Sm2()}

func (sch *sm2Scheme) Name() string { return "SM2" }

func (sch *sm2Scheme) PublicKeySize() int {
	return 2*((sch.curve.Params().BitSize + 7) / 8) + 1
}

func (sch *sm2Scheme) PrivateKeySize() int {
	return (sch.curve.Params().N.BitLen() + 7) / 8
    //return (sch.curve.Params().N.BitLen() + 7) / 8
}

func (sch *sm2Scheme) SeedSize() int              { return sch.PrivateKeySize() }
func (sch *sm2Scheme) SharedKeySize() int         { return (sch.curve.Params().BitSize + 7) / 8 }
func (sch *sm2Scheme) CiphertextSize() int        { return 129 }
func (sch *sm2Scheme) EncapsulationSeedSize() int { return sch.SeedSize() }

// 添加 Scheme 方法 - 修復缺少的方法
func (pk *sm2PublicKey) Scheme() kem.Scheme { return pk.scheme }
func (sk *sm2PrivateKey) Scheme() kem.Scheme { return sk.scheme }

// 添加 Public 方法 - 修復缺少的方法
func (sk *sm2PrivateKey) Public() kem.PublicKey {
    x, y := sk.scheme.curve.ScalarBaseMult(sk.key)
    return &sm2PublicKey{
        sk.scheme,
        x,
        y,
    }
}

// GenerateKeyPair 生成 SM2 密钥对
func (sch *sm2Scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        return nil, nil, err
    }
    return &sm2PublicKey{sch, priv.X, priv.Y}, &sm2PrivateKey{sch, priv.D.Bytes()}, nil
}

// DeriveKeyPair 从种子派生密钥对
func (sch *sm2Scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
    h := xof.SHAKE256.New()
    h.Write(seed)
    key := make([]byte, sch.PrivateKeySize())
    h.Read(key)

    d := new(big.Int).SetBytes(key)
    x, y := sch.curve.ScalarBaseMult(d.Bytes())
    return &sm2PublicKey{sch, x, y}, &sm2PrivateKey{sch, key}
}

// Encapsulate 封装共享密钥
func (sch *sm2Scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {


    sm2Pub, ok := pk.(*sm2PublicKey)
    if !ok {
      return nil, nil, kem.ErrTypeMismatch
    }
    ss = make([]byte, sch.SharedKeySize())
    if _, err := rand.Read(ss); err != nil {
      return nil, nil, err
    }
	curve := sm2.P256Sm2()
    ct, err = sm2.Encrypt(&sm2.PublicKey{curve, sm2Pub.x,  sm2Pub.y}, ss, rand.Reader, sm2.C1C3C2)
    return ct, ss, err
}

// EncapsulateDeterministically 确定性封装
func (sch *sm2Scheme) EncapsulateDeterministically(pk kem.PublicKey, seed []byte) (ct, ss []byte, err error) {



    sm2Pub, ok := pk.(*sm2PublicKey)
    if !ok {
      return nil, nil, kem.ErrTypeMismatch
    }
    h := sha3.NewShake256()
    h.Write(seed)
    ss = make([]byte, sch.SharedKeySize())
    h.Read(ss)
	curve := sm2.P256Sm2()
    ct, err = sm2.Encrypt(&sm2.PublicKey{curve, sm2Pub.x,  sm2Pub.y}, ss, rand.Reader, sm2.C1C3C2)
    return ct, ss, err
}

// Decapsulate 解封装共享密钥
func (sch *sm2Scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {


    sm2Priv, ok := sk.(*sm2PrivateKey)
    if !ok {
       return nil, kem.ErrTypeMismatch
    }
    priv := &sm2.PrivateKey{
       PublicKey: sm2.PublicKey{Curve: sm2.P256Sm2(),X: sm2Priv.scheme.curve.Params().Gx, Y: sm2Priv.scheme.curve.Params().Gy},
       D:         new(big.Int).SetBytes(sm2Priv.key),
    }
    return sm2.Decrypt(priv, ct, sm2.C1C3C2)
}

// UnmarshalBinaryPublicKey 反序列化公钥
func (sch *sm2Scheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
    x, y := elliptic.Unmarshal(sch.curve, buf)
    return &sm2PublicKey{sch, x, y}, nil
}

// UnmarshalBinaryPrivateKey 反序列化私钥
func (sch *sm2Scheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
    return &sm2PrivateKey{sch, buf}, nil
}

// MarshalBinary 公钥序列化
func (pk *sm2PublicKey) MarshalBinary() ([]byte, error) {
    return elliptic.Marshal(pk.scheme.curve, pk.x, pk.y), nil
}

// Equal 公钥比对
func (pk *sm2PublicKey) Equal(other kem.PublicKey) bool {
    oth, ok := other.(*sm2PublicKey)
    return ok && pk.x.Cmp(oth.x) == 0 && pk.y.Cmp(oth.y) == 0
}

// MarshalBinary 私钥序列化
func (sk *sm2PrivateKey) MarshalBinary() ([]byte, error) {
    return sk.key, nil
}

// Equal 私钥比对
func (sk *sm2PrivateKey) Equal(other kem.PrivateKey) bool {
    oth, ok := other.(*sm2PrivateKey)
    return ok && subtle.ConstantTimeCompare(sk.key, oth.key) == 1
}