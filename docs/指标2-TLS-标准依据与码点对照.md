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
