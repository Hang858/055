# 指标 2 · TLS 部分的标准依据、码点与实测长度对照

> 本文是 [`指标2-TLS协议量子安全等级论证.md`](指标2-TLS协议量子安全等级论证.md) 的支撑材料，集中列出
> 正文引用的标准编号、TLS 码点、算法参数尺寸与本课题实测数据，供核对使用。

## 一、标准依据

| 标准 | 标题与状态 | 与 TLS 抗量子的关系 |
|---|---|---|
| RFC 9846 | The Transport Layer Security (TLS) Protocol Version 1.3，2026-07 | TLS 1.3 基础协议：supported_groups/key_share（§4.2.8）、signature_algorithms、Certificate/CertificateVerify、HKDF 密钥调度 |
| RFC 9954 | Hybrid Key Exchange in TLS 1.3，Informational，2026-07 | 混合密钥交换框架：§3.1 以 NamedGroup 协商、§3.2 公钥与密文直接拼接且不带长度字段、§3.3 共享秘密拼接后作为 (EC)DHE 输入送入密钥调度、§4 长度上限 2^16−1、§6 双 PRF 组合器安全性 |
| RFC 10024 | Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3，Standards Track，2026-08 | 具体 PQ/T 混合组 X25519MLKEM768、SecP256r1MLKEM768、SecP384r1MLKEM1024；废弃标准化前的 Kyber768 实验码点 |
| RFC 9794 | Terminology for Post-Quantum Traditional Hybrid Schemes，2025-06 | PQ/T 混合方案术语 |
| FIPS 203 / 204 / 205 | ML-KEM / ML-DSA / SLH-DSA 标准 | 抗量子 KEM 与签名算法的参数集与安全类别 |
| RFC 9881 / RFC 9909 | ML-DSA / SLH-DSA 的 X.509 算法标识 | 抗量子证书的公钥与签名算法标识（OID） |
| NIST 公告（2025-03） | NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | HQC 的标准化状态（第五个待标准化 KEM，尚未成为 FIPS） |

## 二、TLS 密钥交换算法（Supported Groups）码点

| 群名称 | 码点 | 组合与量子安全等级 | 依据 |
|---|---|---|---|
| MLKEM512 / MLKEM768 / MLKEM1024 | 512 / 513 / 514（0x0200–0x0202） | 纯抗量子 ML-KEM，128 / 192 / 256 比特 | IANA TLS Supported Groups |
| SecP256r1MLKEM768 | 4587（0x11EB） | secp256r1 + ML-KEM-768，192 比特 | RFC 10024 |
| X25519MLKEM768 | 4588（0x11EC，Recommended=Y） | X25519 + ML-KEM-768，192 比特 | RFC 10024 |
| SecP384r1MLKEM1024 | 4589（0x11ED） | secp384r1 + ML-KEM-1024，256 比特 | RFC 10024 |
| curveSM2MLKEM768 | 4590（0x11EE） | SM2 + ML-KEM-768，192 比特 | 草案 draft-yang-tls-hybrid-sm2-mlkem-03 |
| X25519Kyber768Draft00 | 25497（0x6399） | 标准化前的 Kyber768 实验码点，已废弃 | RFC 10024 §7.4 |
| 私用段 | 65024–65279（0xFE00–0xFEFF） | HQC 及自定义混合组合使用该段 | RFC 9846 / IANA |

长度核对（RFC 10024 §4.1–§4.3，可直接抓包验证）：

| 群 | 客户端 key_exchange | 服务端 key_exchange | 共享秘密 |
|---|---|---|---|
| X25519MLKEM768 | 1216 = ML-KEM-768 封装公钥 1184 + X25519 32 | 1120 = ML-KEM 密文 1088 + X25519 32 | 64 |
| SecP256r1MLKEM768 | 1249 = secp256r1 65 + ML-KEM 1184 | 1153 = secp256r1 65 + ML-KEM 1088 | 64 |
| SecP384r1MLKEM1024 | 1665 = secp384r1 97 + ML-KEM 1568 | 1665 = secp384r1 97 + ML-KEM 1568 | 80 |

> 注意：`X25519MLKEM768` 的名称顺序与拼接顺序相反（实际为 ML-KEM 在前、X25519 在后），
> `SecP256r1MLKEM768`、`SecP384r1MLKEM1024` 则是 ECDHE 在前，核对字节时必须按此顺序判断。

## 三、TLS 签名算法（SignatureScheme）码点

| 算法 | 码点 | 量子安全等级 | X.509 算法标识 |
|---|---|---|---|
| ML-DSA-44 / ML-DSA-65 / ML-DSA-87 | 0x0904 / 0x0905 / 0x0906 | 安全类别 2 / 3 / 5（128 / 192 / 256 比特） | RFC 9881 |
| SLH-DSA-SHA2 与 SHAKE 12 组 | 0x0911–0x091C | 128 / 192 / 256 比特 | RFC 9909 |
| 私用段 | 0xFE00–0xFFFF | 自定义签名算法使用该段 | RFC 9846 |

## 四、本课题已实现的混合组合与实测 key_share 长度

| 混合组合 | 码点 | 量子安全等级 | ClientHello key_share | ServerHello key_share |
|---|---|---|---|---|
| SM2Kyber512Draft00（SM2 + Kyber-512） | 0xfe34（私用段） | 128 比特 | 865 = SM2 公钥 65 + 800 | 897 = SM2 密文 129 + 768 |
| X25519Kyber512Draft00 | 0xfe30（私用段） | 128 比特 | 832 = 32 + 800 | 800 = 32 + 768 |
| X25519Kyber768Draft00 | 0x6399（已废弃码点） | 192 比特 | 1216 = 32 + 1184 | 1120 = 32 + 1088 |
| SM2Kyber1024Draft00（SM2 + Kyber-1024） | 0xfe37（私用段） | 256 比特 | 1633 = 65 + 1568 | 1697 = 129 + 1568 |
| X25519Kyber1024Draft00 | 0xfe36（私用段） | 256 比特 | 1600 = 32 + 1568 | 1600 = 32 + 1568 |
| X25519HQC-128 | 0xfe38（私用段） | 128 比特 | 2281 = 32 + 2249 | 4465 = 32 + 4433 |
| X25519HQC-256 | 0xfe39（私用段） | 256 比特 | 7277 = 32 + 7245 | 14453 = 32 + 14421 |

上表长度已通过真实抓包与解析脚本 `tools/tls_hello_check.py` 逐组验证（该脚本内置 RFC 9954 §3.2 的
预期长度表，可对抓包直接断言）；证书侧已实现并验证 ML-DSA-44/65/87、SLH-DSA-SHA2-128s/192f/256s
以及「SM2 + ML-DSA-87」等双重签名证书链。

## 五、术语与 TLS 1.3 密钥调度说明（配合正文第 2 点阅读）

**(EC)DHE**：(Elliptic Curve) Diffie-Hellman Ephemeral，即（椭圆曲线）临时 Diffie-Hellman 密钥交换。
"Ephemeral" 表示双方每次握手都用**一次性临时私钥**，用完即弃，因而具备前向保密（即使长期私钥泄露也
解不开历史会话）。在 TLS 1.3 的密钥调度图中，`(EC)DHE` 是**一个输入槽位的名字**，承载本次密钥交换
算出的共享秘密；传统握手里填 ECDH 的共享秘密，混合握手里则填 `K_CL ‖ K_PQ` 的拼接结果
（RFC 9954 §3.3）。写成"(EC)DHE"是因为 TLS 既支持有限域 DH，也支持椭圆曲线 ECDH。

**HKDF**：HMAC-based Extract-and-Expand Key Derivation Function，基于 HMAC 的"提取—扩展"密钥派生
函数（RFC 5869）。它分两步：`HKDF-Extract(salt, 输入密钥材料) -> 伪随机密钥 PRK`，
`HKDF-Expand(PRK, info, 长度) -> 输出密钥`。TLS 1.3 用密码套件指定的哈希（SHA-256 或 SHA-384）实例化
HKDF，并额外定义了两个封装：
`HKDF-Expand-Label(Secret, Label, Context, Length)`（把标签与上下文编码后调用 HKDF-Expand）和
`Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)`
（用"到目前为止全部握手报文的哈希"作为上下文，从而把派生出的密钥与本次握手的报文绑定）。

**TLS 1.3 密钥调度**（RFC 9846，混合密钥交换插在 (EC)DHE 位置）：

```
       0
       |
       v
 PSK -> HKDF-Extract = Early Secret
       |
       v  Derive-Secret(., "derived", "")
       |
K_CL‖K_PQ -> HKDF-Extract = Handshake Secret          <-- 混合共享秘密在此进入
       |
       +--> Derive-Secret(., "c hs traffic", ClientHello…ServerHello) = client_handshake_traffic_secret
       +--> Derive-Secret(., "s hs traffic", ClientHello…ServerHello) = server_handshake_traffic_secret
       |
       v  Derive-Secret(., "derived", "")
       |
       0 -> HKDF-Extract = Master Secret
       |
       +--> Derive-Secret(., "c ap traffic", …server Finished) = client_application_traffic_secret_0
       +--> Derive-Secret(., "s ap traffic", …server Finished) = server_application_traffic_secret_0
       +--> Derive-Secret(., "exp master", …server Finished)   = exporter_master_secret
       +--> Derive-Secret(., "res master", …client Finished)   = resumption_master_secret
```

**握手流量密钥（handshake traffic secret）**：由 Handshake Secret 派生，用于保护**握手阶段**的报文——
服务端的 EncryptedExtensions、Certificate、CertificateVerify、Finished 以及客户端的 Finished。
由此，证书与签名从 ServerHello 之后就是在加密信道中传输的。

**应用流量密钥（application traffic secret）**：由 Master Secret 派生，用于保护**应用数据**；通信过程中
可通过 KeyUpdate 更新（下标递增为 `..._traffic_secret_N`）。

两者本身是"密钥材料"，真正的 AEAD 参数再从它们导出：
`写密钥 = HKDF-Expand-Label(流量密钥, "key", "", 密钥长度)`（AES-128-GCM 为 16 字节、AES-256-GCM 为
32 字节），`初始向量 IV = HKDF-Expand-Label(流量密钥, "iv", "", 12)`；每条记录再带上 5 字节记录头与
16 字节认证标签。

**导出密钥（exporter_master_secret）**：供上层应用通过 `ExportKeyingMaterial` 派生自己的密钥，本课题
TLS-3-2 用例即用该机制派生应用层密钥并完成加解密。

## 六、本课题 TLS 侧算法能力与标准/草案对照（核对表）

| 能力 | 实现情况 | 标准/码点 | 说明 |
|---|---|---|---|
| 混合密钥交换的拼接构造 | 已实现并通过抓包验证 | **RFC 9954**（Informational，2026-07） | 公钥/密文直接拼接、不带长度字段；拼接后的共享秘密作为 (EC)DHE 输入送入 HKDF 密钥调度 |
| X25519MLKEM768 | 协议栈已支持该标准混合组（0x11ec，ML-KEM-768 参数集） | **RFC 10024**（Standards Track），码点 4588 | 项目测试命令行以自定义混合组名为主，栈内该组可直接协商 |
| SM2Kyber512Draft00 / SM2Kyber768Draft00 / SM2Kyber1024Draft00 | 已实现并实测（865/897、1633/1697 字节等） | 私用码点 0xfe34 / 0xfe35 / 0xfe37 | 国密与抗量子混合在 IETF 为草案 curveSM2MLKEM768（码点 4590） |
| X25519Kyber512/768/1024Draft00 | 已实现并实测 | 0x6399 为 Kyber768 草案码点（RFC 10024 已将其列为废弃） | 参数集与 ML-KEM-512/768/1024 相同 |
| X25519HQC-128 / X25519HQC-256 | 已实现并实测（需 `-tags pq_hqc` 与 liboqs） | 私用码点 0xfe38 / 0xfe39 | HQC 处于 NIST 标准化推进阶段，暂无 IANA 码点 |
| 纯抗量子组 MLKEM512/768/1024 | 栈内支持 ML-KEM-768 参数集；512/1024 由同为该参数集的 Kyber 实现承载 | IANA 码点 512/513/514 | 可按需补充独立组名 |
| TLS 抗量子/混合签名与证书 | 协议栈通过 `PQSignatureSchemesEnabled` 支持 Ed25519-Dilithium2/3 混合签名方案；证书体系生成并验证 Dilithium2/3/5（ML-DSA 参数集）、SLH-DSA 12 组与 SM2 双重签名证书链 | draft-ietf-tls-mldsa（ML-DSA 码点 0x0904–0x0906）、RFC 9881 / RFC 9909（X.509 算法标识） | 抗量子公钥与签名经 Certificate、CertificateVerify 承载并验证 |
