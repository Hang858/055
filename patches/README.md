# Go 1.22.12 crypto/tls 抗量子补丁

这份补丁是 `tls-hybrid/` 与 `pqtls-1.3/` 源码库能提供抗量子混合密钥交换的**前提**：
它给标准库 `crypto/tls` 加上了 Cloudflare CIRCL 的混合 KEM（Kyber 系）和
Ed25519-Dilithium 混合签名，并把部分 Go 1.24 时代的 TLS 特性（ECH、委托凭证、HPKE、metrics）
回移进了 1.22.12。

| 文件 | 说明 |
|---|---|
| `go1.22.12-crypto-tls.patch` | `src/crypto/tls/**` 与 `src/vendor/modules.txt` 的完整 diff（8067 行，`-p1` 可用；2026-09 增补 SM2+HQC 两组后重新生成） |
| `vendor-circl.tgz` | 补丁新增的 `src/vendor/github.com/cloudflare/circl` 目录（解压即用） |
| `PATCH-SURFACE.txt` | 补丁后的 GOROOT 与官方 Go 1.22.12 的完整差异清单（含构建生成物、遗留目录） |
| `go1.22.12-sm2-mldsa-auth.patch` | 在上一补丁之上增加 TLS 1.3 SM2+ML-DSA-44/87 服务端认证入口；须在第一份补丁之后应用 |
| `go1.22.12-sm2-mldsa-mtls.patch` | 在服务端认证补丁之上增加双向认证、实际签名码点和已验证原始证书链状态 |

## 应用方法

见 `../docs/BUILD.md` 的「A. 重建打补丁的 Go 1.22.12」。要点：

```sh
tar xzf go1.22.12.src.tar.gz && cd go
patch -p1 < /path/to/patches/go1.22.12-crypto-tls.patch
patch -p1 < /path/to/patches/go1.22.12-sm2-mldsa-auth.patch
patch -p1 < /path/to/patches/go1.22.12-sm2-mldsa-mtls.patch
tar xzf /path/to/patches/vendor-circl.tgz -C src/vendor/github.com/cloudflare
GOROOT_BOOTSTRAP=/usr/lib/go-1.22 ./src/make.bash
```

新增的服务端认证补丁已在上一补丁形成的源码上重放，并与本地测试源码逐字节比对。新增部分不把旧 Dilithium 实现改名为 ML-DSA；标准 ML-DSA 实现由网关模块中的 CIRCL 1.6.3 提供。

新增补丁提供`tls.SM2WithMLDSA44`（`0xfea0`）、`tls.SM2WithMLDSA87`（`0xfea1`）、`Config.HybridAuthScheme`、`Config.VerifyHybridServer`和`Config.VerifyHybridClient`。只有显式设置混合认证策略才宣告私有码点。TLS 代码把原始证书链及`CertificateVerify`待签名输入交给网关证书适配层校验；会话恢复被禁用。`ConnectionState`返回实际使用的混合签名码点和已验证的原始对端证书链。

## 变更内容

**新增（16 个，都在 `src/crypto/tls/`）**

- 抗量子核心：`cfkem.go`（CurveID→CIRCL 混合 KEM 映射）、`tls_cf.go`（CIRCL 签名方案注册）、`cfevent.go`
- 回移的 TLS 特性：`ech.go`、`ech_config.go`、`ech_provider.go`、`hpke.go`、`delegated_credentials.go`、`generate_delegated_credential.go`
- 测试：`cfkem_test.go`、`cfgo_test.go`、`tls_cf_test.go`、`tls_cf_circl_test.go`、`ech_test.go`、`delegated_credentials_test.go`、`metrics_test.go`

**修改（18 个）**

- `common.go`（`signatureEdDilithium2/3`、`PQSignatureSchemesEnabled`）、`conn.go`、`alert.go`、`auth.go`、`tls.go`、`prf.go`、`generate_cert.go`
- 握手主路径：`handshake_client.go`、`handshake_client_tls13.go`、`handshake_server.go`、`handshake_server_tls13.go`、`handshake_messages.go`、`key_agreement.go`
- 对应测试：`auth_test.go`、`handshake_test.go`、`handshake_messages_test.go`、`handshake_server_test.go`、`tls_test.go`

**vendor**

- 新增 `github.com/cloudflare/circl v1.4.1-0.20240905130006-2d6cd9871f69`
- 新增 `golang.org/x/crypto/{blake2b,blake2s}`
- 修改 `src/vendor/modules.txt`

## 已支持 / 未支持的抗量子算法

| 类别 | 已实现 | 备注 |
|---|---|---|
| 混合密钥交换（128 比特） | `X25519Kyber512Draft00`(0xfe30)、`SM2Kyber512Draft00`(0xfe34) | 见 `cfkem.go` |
| 混合密钥交换（192 比特） | `X25519Kyber768Draft00`(0x6399)、`X25519Kyber768Draft00Old`(0xfe31)、`P256Kyber768Draft00`(0xfe32)、`SM2Kyber768Draft00`(0xfe35) | |
| 混合密钥交换（**256 比特**） | **`X25519Kyber1024Draft00`(0xfe36)、`SM2Kyber1024Draft00`(0xfe37)** | 本次新增。X25519 配对由 `hybrid.Kyber1024X25519()` 提供（CIRCL 原本只有 Kyber1024-X448 / Kyber1024-sm2） |
| 其他 | `X25519MLKEM768`(0x11ec) | 只定义了码点，示例未启用 |
| 签名 | `Ed25519+Dilithium2/3`（`EdDilithium2/3`） | 需 `Config.PQSignatureSchemesEnabled = true`，默认关闭 |
| **HQC（可选编译）** | **`X25519HQC-128`(0xfe38)、`X25519HQC-256`(0xfe39)、`SM2HQC-128`(0xfe3a)、`SM2HQC-256`(0xfe3b)** | CIRCL 不含 HQC，适配器走 cgo 调 liboqs；SM2 混合组用 CIRCL 的 SM2 KEM（新增导出 `hybrid.SM2KEM()`）与 HQC 组合。四组均需 `-tags pq_hqc` 构建，默认构建下不可用。见 `../docs/HQC-TLS-最小改造路线.md` |

`tls-hybrid` 的客户端与服务端都支持 `-kex` 参数只启用某一组，便于逐组测试：

```sh
./e2e -kex X25519Kyber1024Draft00   # 256 比特
./e2e -kex X25519Kyber512Draft00    # 128 比特
./e2e -kex SM2Kyber512Draft00       # 国密 128 比特
./e2e -kex X25519HQC-128            # 128 比特（需 -tags pq_hqc 构建）
./e2e -kex X25519HQC-256            # 256 比特（需 -tags pq_hqc 构建）
./e2e -kex SM2HQC-128               # 国密 + 编码类抗量子：SM2 + HQC-128（需 -tags pq_hqc）
./e2e -kex SM2HQC-256               # 国密 + 编码类抗量子：SM2 + HQC-256（需 -tags pq_hqc）
```

## 遗留（未纳入补丁）

补丁后的 GOROOT 里还有两处**没有任何代码引用**的目录，属于开发过程残留，
建议重建时不要拷贝（它们不影响编译）：

- `src/crypto/tls1/`（1.9M）——另一份 crypto/tls 副本
- `src/vendor1/`（5.9M）——另一份 vendor 备份

另外 `PATCH-SURFACE.txt` 里列出的 `zdefaultcc.go`、`zbootstrap.go`、`zversion.go`、
`zzipdata.go`、`zcgo.go` 是 `make.bash` 的生成物，不属于补丁内容。
