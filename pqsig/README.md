# pqsig：签名算法抽象

TLS、KEMTLS-lab 和证书工具共用的签名算法注册表。目标不是再加一套 `if dilithium` 分支，而是把算法差异收敛到一个 `Algorithm` 接口。

## 已支持的算法

| 名称 | 族 | 安全级别 | 公钥 | 私钥 | 签名 |
|---|---|---:|---:|---:|---:|
| `Dilithium2` | Dilithium | 128 | 1312 B | 2528 B | 2420 B |
| `SLH-DSA-SHA2-128s` | SLH-DSA | 128 | 32 B | 64 B | 7856 B |
| `SLH-DSA-SHA2-128f` | SLH-DSA | 128 | 32 B | 64 B | 17088 B |
| `SLH-DSA-SHA2-192s` | SLH-DSA | 192 | 48 B | 96 B | 16224 B |
| `SLH-DSA-SHA2-192f` | SLH-DSA | 192 | 48 B | 96 B | 35664 B |
| `SLH-DSA-SHA2-256s` | SLH-DSA | 256 | 64 B | 128 B | 29792 B |
| `SLH-DSA-SHA2-256f` | SLH-DSA | 256 | 64 B | 128 B | 49856 B |

## 接口

```go
type Algorithm interface {
    Name() string
    Family() Family
    Level() int
    OID() asn1.ObjectIdentifier
    Scheme() sign.Scheme

    PublicKeySize() int
    PrivateKeySize() int
    SignatureSize() int

    GenerateKey() (*KeyPair, error)
    Sign(priv *PrivateKey, message []byte) ([]byte, error)
    Verify(pub *PublicKey, message, signature []byte) error

    ParsePublicKey(raw []byte) (*PublicKey, error)
    ParsePrivateKey(raw []byte) (*PrivateKey, error)
}
```

调用方只拿 `Algorithm`，不关心底层是 CIRCL 的 `mode2` 还是 `slhdsa`：

```go
alg, _ := pqsig.ByName("SLH-DSA-SHA2-128s")
kp, _ := alg.GenerateKey()
sig, _ := alg.Sign(kp.Private, msg)
err := alg.Verify(kp.Public, msg, sig)
```

## 测试

```bash
GOMODCACHE=$PWD/../.build/gomodcache-sm2auth \
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
go test -v -timeout 10m ./...
```

本机结果：

```text
PASS: TestRegistryHasAllAlgorithms
PASS: TestSignVerifyAllAlgorithms (7 个子测试)
PASS: TestKeyRoundTrip
ok  	pqsig	2.547s
```

## 证书扩展

证书工具现有的混合证书已经在 `1.3.6.1.4.1.54321.1.1` / `.1.2` 扩展里使用
`PQExtension{Algorithm OID, Data}`，所以 certtool 生成的混合证书已经带算法标识。

`myx509`/`go_kemtls` 的旧扩展是裸公钥/裸签名，没有算法标识。`pqsig` 为这部分提供：

```go
var OIDAlgorithmExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 3}

der, err := pqsig.EncodeAlgorithmExtension(alg)
alg, err := pqsig.DecodeAlgorithmExtension(der)
```

后续给 `myx509` 打补丁时，用这个扩展区分 Dilithium2 和六档 SLH-DSA；没有扩展时按旧行为默认 Dilithium2。

## 下一步

1. 在证书扩展中增加算法标识（不能只放裸公钥/签名，否则 Dilithium2 和 SLH-DSA 无法区分）。
2. 把 `myx509` 和 `go_kemtls` 的硬编码 `mode2` 改为查 `pqsig` 注册表。
3. 给 TLS 增加 SLH-DSA SignatureScheme 和 CertificateVerify 分支。
4. 给 `TLS-1-13` 增加 Sign 侧 SLH-DSA 变体。

## 注意

- SLH-DSA 签名尺寸远大于 Dilithium2，256f 约 49 KB，不能直接用于高频 TLS 握手。
- 当前 `OID()` 中 Dilithium2 使用项目私有 OID，SLH-DSA 使用 RFC 9909 的 `.3.20`～`.25`；证书扩展接入后以扩展里的算法标识为准。
