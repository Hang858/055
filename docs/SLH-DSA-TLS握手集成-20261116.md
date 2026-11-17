# SLH-DSA 接入 TLS 握手

日期：2026-11-16
范围：patched Go `go_kemtls` 的服务端和客户端 CertificateVerify，覆盖 Dilithium2/3/5 与六档 SLH-DSA-SHA2。

## 已完成的链路

`crypto/tls`：

- 新增私有 SignatureScheme：
  - Dilithium2/3/5：`0xFE01/0xFE02/0xFE03`
  - SLH-DSA-SHA2-128s/128f/192s/192f/256s/256f：`0xFE10`～`0xFE15`
- `typeAndHashFromSignatureScheme`、`supportedSignatureAlgorithms` 增加对应映射。
- `Config` 增加 `KEMTLSSigAlg`、`KEMTLSSigKey`，用于选择服务端 PQ 签名算法和私钥。
- 服务端 CertificateVerify 按配置算法签名，不再写死 Dilithium2。
- 客户端按 `certVerify.signatureAlgorithm` 和证书 `.1.3` 算法扩展验签。
- 客户端 CertificateVerify 也支持 `KEMTLSSigAlg/KEMTLSSigKey`，服务端按客户端证书 `.1.3` 扩展验签。

`crypto/myx509`：

- 新增 `OIDQuantumAlgorithm = 1.3.6.1.4.1.54321.1.3`。
- 新增 `QuantumAlgorithmFromCert`。
- 新增 `QuantumSignWithLocalKeyAlg`、`VerifyQuantumSignatureFromCertAlg`。
- 支持 Dilithium2/3/5 和六档 SLH-DSA-SHA2。

工具链：

- `.build/extracted/go_kemtls` 已打入 vendored CIRCL `sign/slhdsa`、`mode5`、`x/crypto/sha3`。
- `.build/go-kemtls-min.tgz` 已重新打包（约 69 MB）。
- 补丁见 `packaging/tls-source/patches/slhdsa-tls-handshake.patch`。

## 证书格式

测试证书由 `pqsig/cmd/pqcertlab` 生成：

- 经典部分：RSA 2048 根 CA、服务端叶、客户端叶。
- 服务端叶扩展：
  - `.1.1`：SLH-DSA/Dilithium 原始公钥
  - `.1.3`：算法 OID（DER）
- 客户端证书同样带 `.1.1` 原始 PQ 公钥和 `.1.3` 算法 OID，服务端据此验证客户端 CertificateVerify。
- 双方先验证标准 RSA 证书链和 SAN，再做 PQ 签名验证。

## 测试

脚本：`pqsig/run-tls-matrix.sh`

九种签名算法逐个生成证书、启动 TLS 服务端、跑一次完整握手：

```text
PASS: TLS handshake Dilithium2
PASS: TLS handshake Dilithium3
PASS: TLS handshake Dilithium5
PASS: TLS handshake SLH-DSA-SHA2-128s
PASS: TLS handshake SLH-DSA-SHA2-128f
PASS: TLS handshake SLH-DSA-SHA2-192s
PASS: TLS handshake SLH-DSA-SHA2-192f
PASS: TLS handshake SLH-DSA-SHA2-256s
PASS: TLS handshake SLH-DSA-SHA2-256f
PASS: missing SLH-DSA key fails

passed=10 failed=0
```

SLH-DSA-128s 单次握手约 820 ms（本机回环，含双方 SLH 签名/验签）。

## 当前边界

- 已经接了**服务端和客户端 CertificateVerify**，Sig-Sig 模式下双方都用 SLH-DSA 认证。
- KEM-Sig / Sig-KEM 的 KEM 证书认证仍受 `persistentssKEM` 问题影响，不在本次 SLH 修改范围内。
- KEM 证书认证的 `persistentssKEM` 问题仍独立存在，不在本次 SLH 修改范围内。
- SLH-DSA 签名 7.8 KB～49 KB，握手报文明显变大，需要继续测分片、时延和中间盒兼容性。
- 这些码点是项目私有值，不是标准 TLS SignatureScheme，不能和标准栈互通。

## 复现

```bash
# 1. 构建工具链（已包含在 .build/go-kemtls-min.tgz）
# 2. 构建 KEMTLS TLS 服务端/客户端（ProtocolType=11）
# 3. 构建 pqsig 工具
cd pqsig
go build -o ../.build/pqkey ./cmd/pqkey
go build -o ../.build/pqcertlab ./cmd/pqcertlab
cd ..
# 4. 跑九档 TLS 握手矩阵
bash pqsig/run-tls-matrix.sh
```
