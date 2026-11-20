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

## kem-registry-tls.patch

对应 2026-11-20 的 C 算法注册机制接入：

- 新增 `src/crypto/pq/`：C ABI `pq_alg.h`、注册表、占位符，以及 cgo Go 包装；
- `crypto/myx509`：读取证书 `.1.4` 的 KEM 算法 OID，按 `pq.Lookup` 封装/解封装；
  没有 `.1.4` 时保持 Kyber768 旧行为；
- `crypto/tls`：增加 `Config.KEMTLSKEMAlg/KEMTLSKEMKey`，KEM 证书路径按配置选择算法；
  解封装/封装错误不再忽略，改为告警并终止；
- 客户端 `type 252` 的密文长度改为按实际头解析，不再写死 Kyber768 长度；
- 将两段 KEM SS 绑定到 client Finished（`kemFinishedHash`），错误 KEM 私钥会被拒绝。

应用前提：

1. 先应用 `slhdsa-tls-handshake.patch`（或使用已包含它的工具链）；
2. 构建时需要 `CGO_ENABLED=1` 和 C 编译器，因为 `crypto/pq` 通过 cgo 调用 C 注册表；
3. `src/crypto/pq/` 中的 `BiT`/`KEM-TEMPLATE` 是占位描述符，真实算法到位后替换
   `pq_bit_placeholder.c`/新增 C 适配器，不需要改 TLS 层。

应用方式：

```bash
patch -p1 < kem-registry-tls.patch
```

安全边界：该补丁让 KEM 证书路径可以按注册表选择算法，并把 KEM SS 绑定到 client Finished。
KEM SS 进入应用密钥调度由后续的 `kem-key-schedule.patch` 完成；即使应用补丁后，
KEM 证书模式仍是“ECDHE 握手 + KEM 认证/密钥绑定”，不是完整的 KEMTLS。

## protocol-mode-negotiation.patch

对应 2026-11-20 的协议类型协商：

- ClientHello 增加 `0xFFF3` 支持列表扩展，首项为首选；
- `Config.ProtocolTypes` + `Config.ModeCompatibilityFlag`，语义与论文
  `modeCompatibilityFlag` 对齐；旧 `ProtocolTypeStrict` 保留兼容；
- 服务端按客户端优先级选共同类型，强制模式只接受本端首选或 `ClassicAKE`，
  交集为空则 `handshake_failure`；客户端校验选择必须来自自己通告的列表；
- 补齐 12/20/22/23 组合；HRR 选择客户端尚未发送 key_share 的经典曲线，
  ServerHello/HRR 携带完整组合编号；
- 服务端能力判断会使用 `signature_algorithms_cert`，客户端未声明 PQ 证书
  验签算法时不选 PQ 签名认证。

应用顺序：

```bash
patch -p1 < slhdsa-tls-handshake.patch
patch -p1 < kem-registry-tls.patch
patch -p1 < protocol-mode-negotiation.patch
```

测试矩阵与边界见 `docs/协议类型协商-20261120.md`。


## kem-key-schedule.patch

对应 2026-11-20 的 KEM 密钥调度接入（阶段 2）：

- `crypto/internal/fips140/tls13` 增加 `MasterSecret.WithKEMSecret`；
- KEM 证书模式在拿到 `ssServer`/`ssClient` 后，把
  `HKDF-Extract(salt=master, IKM=ssServer||ssClient)` 作为新的 master；
- 应用流量密钥、exporter、resumption secret 改为从新 master 派生；
- 服务端在 type 252 发送之后才安装应用写密钥；客户端收到 252 后才安装应用读密钥；
- `kemFinishedHash` 保留，Finished 仍绑定两段 KEM 秘密。

应用顺序：

```bash
patch -p1 < slhdsa-tls-handshake.patch
patch -p1 < kem-registry-tls.patch
patch -p1 < protocol-mode-negotiation.patch
patch -p1 < kem-key-schedule.patch
```

边界：握手流量密钥仍来自 ECDHE；未实现纯 KEM、0.5-RTT 数据和 KEM 证书链 PQ 验签。
详见 `docs/KEM密钥调度-20261120.md`。
