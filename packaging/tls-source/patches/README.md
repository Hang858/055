# TLS 补丁说明

## serverkeygen-transcript-length.patch

对应论文第 3.3 节的 1.5-RTT 流程优化（`QuantumSupportServerKeyGen`）。

修改两处：

1. 客户端发送 `pqClientKeyExchange` 时使用 `hs.transcript`，把该消息纳入 TLS 1.3 握手摘要；
2. 服务端读取时使用 `hs.transcript`，并在切片前校验内层类型/长度，避免畸形报文触发 panic。

应用方式：解压 `go-kemtls-min.tgz` 后，在 Go 源码根目录执行：

```bash
patch -p1 < serverkeygen-transcript-length.patch
```

然后重新编译客户端/服务端。

## slhdsa-tls-handshake.patch

对应 2026-11-16 的 SLH-DSA TLS 握手接入：

- `crypto/tls` 增加 Dilithium3/5 和六档 SLH-DSA 私有 SignatureScheme；
- 服务端 CertificateVerify 按 `Config.KEMTLSSigAlg/KEMTLSSigKey` 签名；
- 客户端按 CertificateVerify 算法和证书 `.1.3` 扩展验签；
- `crypto/myx509` 增加算法扩展读取、通用 sign/verify。

该补丁只覆盖 Go 源码文件；patched 工具链还需要 vendored CIRCL 的
`sign/slhdsa`、`sign/dilithium/mode5`、`x/crypto/sha3`，这些已经打进
`.build/go-kemtls-min.tgz`。

应用方式：

```bash
patch -p1 < slhdsa-tls-handshake.patch
```
