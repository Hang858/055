# 指标 2 · TLS 协议达到 128、256 比特量子安全等级的论证

> 本文按与 IPsec、SSH 相同的口径撰写：先给出协议的交互逻辑，再说明抗量子改造把哪些密码原语
> 加入了协议的哪个环节，最后论证"协议可达 128、256 比特量子安全等级"这一指标如何由所实例化的
> 抗量子算法满足。文中所有标准编号、码点、参数长度均已逐条核对（依据见 §5）。

## 1. TLS 协议的主要交互过程

TLS 1.3（RFC 9846）采用"密钥交换 + 证书认证"的两段式握手，主要交互过程如下：

1) 客户端发送 **ClientHello**：携带客户端随机数、`supported_versions`（TLS 1.3）、`cipher_suites`
   （对称加密套件）、`supported_groups`（可接受的密钥交换算法/群列表，按偏好降序）、`key_share`
   （针对其中若干群预先给出的密钥交换份额）、`signature_algorithms`（可接受的签名算法列表）等扩展。

2) 服务端回复 **ServerHello**：从客户端 `supported_groups` 中选定一个密钥交换算法（`key_share`
   中给出服务端份额），并选定协议版本与密码套件。若客户端没有为服务端想选的群提供份额，服务端先回
   **HelloRetryRequest**，客户端补发对应份额后再继续（此时多一次往返）。

3) 双方按协商的密钥交换算法计算共享秘密，并在存在 PSK 时与 PSK 一起送入 TLS 1.3 的密钥调度
   （HKDF，RFC 5869），派生出握手流量密钥 `client_handshake_traffic_secret`、
   `server_handshake_traffic_secret`。此后服务端在受保护的信道上发送 `EncryptedExtensions`、
   `Certificate`、`CertificateVerify`、`Finished`，客户端验证证书与签名后回 `Finished`。

4) 身份认证：服务端在 **Certificate** 消息中给出证书链（含签名公钥），并在 **CertificateVerify**
   中用与证书对应的私钥对"签名上下文 + 此前全部握手报文的 Transcript-Hash"进行签名；客户端用
   证书链验证公钥的可信性并验签，从而完成对服务端身份的认证。服务端也可通过 `CertificateRequest`
   要求客户端提供证书，实现双向认证。

5) 握手完成后，由主密钥（master secret）派生出应用流量密钥
   （`client_application_traffic_secret_N`、`server_application_traffic_secret_N`）以及导出密钥
   （`exporter_master_secret`），使用 AEAD 算法（`TLS_AES_128_GCM_SHA256`、
   `TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`）保护应用数据，并可通过 `KeyUpdate`
   更新密钥。

其中第 1)~3) 步决定**通信机密性**，第 4) 步决定**身份真实性**；两者分别由密钥交换原语与签名原语
提供密码学保障。

## 2. TLS 协议的抗量子改造

与 IPsec（IKEv2 的 IKE_SA_INIT / IKE_INTERMEDIATE + IKE_AUTH）和 SSH（密钥交换 + 主机密钥签名）
一致，TLS 的抗量子改造同样是在**密钥交换阶段加入抗量子/混合密钥交换**、在**身份认证阶段加入
抗量子签名认证**：

1) **算法协商阶段**：`supported_groups` 与 `key_share` 中除传统 ECDH 群外，加入抗量子 KEM 群或
   "经典 ECDH + 抗量子 KEM"的混合群；`signature_algorithms` 中加入抗量子签名算法，
   `Certificate`/`CertificateVerify` 中承载抗量子签名公钥与签名。

2) **混合密钥交换的具体交互**（以"ECDH + KEM"混合群为例）：

   ```
   客户端                                                     服务端
     │ ClientHello：supported_groups = [混合群, …]                │
     │             key_share(混合群) = ECDH 公钥 ‖ KEM 封装公钥    │
     │ ─────────────────────────────────────────────────────────► │
     │                                                            │ ① 计算经典 ECDH 共享秘密 K_CL
     │                                                            │ ② 用客户端 KEM 公钥封装 → (KEM 密文, K_PQ)
     │ ◄───────────────────────────────────────────────────────── │
     │ ServerHello：key_share(混合群) = ECDH 公钥 ‖ KEM 密文       │
     │ ① 计算经典 ECDH 共享秘密 K_CL                               │
     │ ② 用本机 KEM 私钥解封装 → K_PQ                              │
     ▼                                                            ▼
         concatenated_shared_secret = K_CL ‖ K_PQ  ──► 作为 (EC)DHE 输入送入 TLS 1.3 密钥调度
   ```

   具体到报文与字节布局，TLS 的做法是**直接拼接、不带任何长度字段或额外编码**
   （RFC 9954 §3.2）：混合群被表示为一个 `NamedGroup`，其 `KeyShareEntry.key_exchange` 就是各分量
   `key_exchange` 的拼接，拼接顺序必须与该 `NamedGroup` 定义中的算法顺序一致；客户端份额是各分量
   公钥（ECDH 份额 / KEM 封装公钥）的拼接，服务端份额是各分量公钥与 KEM 封装密文的拼接。
   共享秘密同样按 `concatenated_shared_secret = ECDH 共享秘密 ‖ KEM 共享秘密` 拼接（RFC 9954 §3.3）。

   **这一点与 SSH 的表述需要区分**：SSH 中最终共享密钥是 K = HASH(K_CL ‖ K_PQ)，即对拼接结果
   再做一次哈希；而 TLS 1.3 **不再额外做一次 HASH**，而是把这个拼接结果**直接作为密钥调度中的
   (EC)DHE 输入**：

   ```
   Handshake Secret = HKDF-Extract( Derive-Secret(Early Secret, "derived", ""),
                                    concatenated_shared_secret )          （RFC 9954 §3.3 图 1）
   ```

   再由 `Derive-Secret` / `HKDF-Expand-Label` 依次派生出上述各类握手与应用流量密钥
   （RFC 9846 的密钥调度）。由于 HKDF-Extract 关于其输入具备 dual-PRF 性质，该构造被证明
   与"双 PRF 组合器"等价（RFC 9954 §6）：**只要经典 ECDH 与抗量子 KEM 任一分量未被攻破，
   派生出的会话密钥即安全**。因此混合组同时具备经典安全与量子安全——量子攻击者可以破解 ECDH
   分量，但只要抗量子 KEM 分量未被攻破，握手密钥仍然安全；反之亦然。混合构造不增加额外往返，
   也保持了与不支持混合群的端点之间的兼容回退（RFC 9954 §1.4）。

3) **身份认证阶段**：服务端（双向认证时还包括客户端）在 `Certificate` 中承载抗量子（或"经典 +
   抗量子"混合）证书，在 `CertificateVerify` 中给出抗量子 DSA 签名；对端用证书中的抗量子公钥验签。
   由于 TLS 1.3 的签名同时覆盖签名上下文与此前全部握手报文的 Transcript-Hash，认证与密钥交换
   被绑定在一起，攻击者无法在不被察觉的情况下替换或降级认证算法。混合签名时需经典签名与抗量子
   签名**同时验证通过**，才认为身份认证通过；该阶段的量子安全能力完全由抗量子 DSA 提供。

4) **量子安全等级的来源**：TLS 的交互逻辑（ClientHello / ServerHello / key_share / 密钥调度 /
   CertificateVerify）本身不携带量子安全能力，量子安全来自被实例化的密码原语。因此：

   - **密钥交换阶段**的量子安全等级取决于抗量子 KEM 算法，以及密钥调度所用的哈希/SHA-2 算法
     （128 比特等级对应 SHA-256，256 比特等级对应 SHA-384）；
   - **身份认证阶段**的量子安全等级取决于抗量子 DSA 算法；
   - **应用数据保护**的等级取决于所选 AEAD 套件（`TLS_AES_128_GCM_SHA256` 为 128 比特、
     `TLS_AES_256_GCM_SHA384` 为 256 比特）；
   - 协议的**整体量子安全等级取上述各环节中最低者**，因此要达到 256 比特，不能只升级签名算法。

## 3. 达到 128、256 比特量子安全等级的算法要求

按前述 NIST 安全类别划分：安全类别 1 表示"抗量子强度至少与 AES-128 的密钥搜索难度相当"，
安全类别 5 表示"至少与 AES-256 相当"。据此，TLS 协议要分别达到 128、256 比特量子安全等级，
其密钥交换与身份认证所使用的抗量子原语应满足：

| 环节 | 128 比特量子安全等级 | 256 比特量子安全等级 | 依据 |
|---|---|---|---|
| 密钥交换（抗量子 KEM） | **ML-KEM-512**（安全类别 1）、**HQC-128** | **ML-KEM-1024**（安全类别 5）、**HQC-256** | FIPS 203；HQC 提交文档 |
| 身份认证（抗量子 DSA） | **ML-DSA-44**（安全类别 2，≥128 比特） | **ML-DSA-87**（安全类别 5） | FIPS 204 |
| 密钥调度哈希 | SHA-256 | SHA-384 | RFC 9846 密钥调度 |
| 应用数据 AEAD | `TLS_AES_128_GCM_SHA256` | `TLS_AES_256_GCM_SHA384` | RFC 9846 |

几点补充说明：

- ML-KEM-512 与 ML-KEM-1024 为 FIPS 203 标准参数集，其公钥/密文分别为 800/768 字节与
  1568/1568 字节，均远小于 TLS `key_exchange` 字段 2^16−1 字节的上限（RFC 9954 §4），可直接承载。
- HQC 于 2025 年 3 月被 NIST 选为第五个待标准化的抗量子 KEM 算法，其 HQC-128/HQC-256 参数集
  分别对应 128/256 比特强度；截至本文写作时 HQC 尚未成为 FIPS 标准，TLS 侧也尚无 IANA 码点，
  因此工程实现需使用私用码点（见 §5）。
- ML-DSA-44 在 FIPS 204 中的安全类别为**类别 2**（要求同时不低于 SHA-256 的抗碰撞强度），
  高于类别 1，故满足"128 比特量子安全等级"；ML-DSA-87 为类别 5，对应 256 比特。
- 需要 256 比特整体等级时，必须同时使用 ML-KEM-1024/HQC-256、ML-DSA-87 **以及**
  `TLS_AES_256_GCM_SHA384`；若密钥交换用 256 比特而对称套件仍选
  `TLS_AES_128_GCM_SHA256`，整体等级会退化为 128 比特。

**结论**：与 IPsec、SSH 相同，要保证 TLS 协议可达到 128、256 比特量子安全，密钥交换和身份认证
都应该达到 128、256 比特量子安全等级，即密钥交换过程的抗量子 KEM 原语的算法构造实例可达到
128、256 比特量子安全等级，身份认证过程的抗量子 DSA 原语的算法构造实例可达到 128、256 比特
量子安全等级。具体而言，使用的密码算法应使用 **ML-KEM-512 和 ML-KEM-1024、HQC-128 和 HQC-256
以及 ML-DSA-44 和 ML-DSA-87**。

## 4. TLS 侧"协议逻辑—密码原语"的实例化对应关系

| 协议环节（交互逻辑） | 无量子安全能力时的原语 | 抗量子实例化后的原语 | TLS 中的承载方式 |
|---|---|---|---|
| 密钥交换：`key_share` 交换公钥/密文 | ECDH（X25519、secp256r1、SM2 等） | KEM：KeyGen / Encaps / Decaps（ML-KEM、HQC）；或 ECDH+KEM 混合 | `supported_groups` 扩展中的 `NamedGroup` + `key_share` 扩展中的 `KeyShareEntry` |
| 共享秘密合成 | 单一 ECDH 共享秘密 | `concatenated_shared_secret = K_CL ‖ K_PQ`，作为 (EC)DHE 输入送入密钥调度 | RFC 9954 §3.3，TLS 1.3 HKDF 密钥调度 |
| 身份认证：对握手报文签名 | RSA / ECDSA / EdDSA / SM2 签名 | ML-DSA、SLH-DSA（或"经典 + 抗量子"混合签名） | `Certificate` + `CertificateVerify`，算法经 `signature_algorithms` 协商 |
| 证书公钥与签名算法标识 | RSA/ECDSA 的 X.509 算法标识 | ML-DSA / SLH-DSA 的 X.509 算法标识（OID） | RFC 9881（ML-DSA）、RFC 9909（SLH-DSA） |
| 密钥派生与应用数据保护 | 经典 HKDF + AES-GCM | HKDF（SHA-256/SHA-384）+ AES-128/256-GCM | RFC 9846 密钥调度与密码套件 |

由上表可见：**密钥交换阶段**的量子安全由 KEM 原语（ML-KEM / HQC）提供，**身份认证阶段**的
量子安全由 DSA 原语（ML-DSA / SLH-DSA）提供，二者与 IPsec、SSH 的对应关系完全一致，区别仅在于
TLS 1.3 把混合共享秘密的合成放在 HKDF 密钥调度的 (EC)DHE 输入位置上。

## 5. 标准依据、码点与当前状态（逐条核对）

### 5.1 协议与框架类标准

| 标准 | 标题与状态 | 与本指标的关系 |
|---|---|---|
| RFC 9846 | The Transport Layer Security (TLS) Protocol Version 1.3，2026-07 | TLS 1.3 基础协议：`supported_groups`/`key_share`（§4.2.8）、`signature_algorithms`、`Certificate`/`CertificateVerify`、HKDF 密钥调度 |
| RFC 9954 | Hybrid Key Exchange in TLS 1.3，Informational，2026-07 | 混合密钥交换框架：§3.1 以 `NamedGroup` 协商、§3.2 公钥/密文直接拼接、§3.3 共享秘密拼接并作为 (EC)DHE 输入、§4 长度上限 2^16−1、§6 dual-PRF 组合器安全性 |
| RFC 10024 | Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3，Standards Track，2026-08 | 具体的 PQ/T 混合组：X25519MLKEM768、SecP256r1MLKEM768、SecP384r1MLKEM1024；并废弃早期 Kyber768 实验码点 |
| RFC 9794 | Terminology for Post-Quantum Traditional Hybrid Schemes，2025-06 | PQ/T 混合方案的术语（traditional / next-generation 等） |
| RFC 5869 | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | TLS 1.3 密钥调度的算法基础 |

### 5.2 密钥交换：TLS Supported Groups 码点

| 群名称 | 码点 | 组合与量子安全等级 | 依据 |
|---|---|---|---|
| MLKEM512 | 512（0x0200） | 纯抗量子 ML-KEM-512，128 比特 | IANA TLS Supported Groups（RFC-ietf-tls-mlkem） |
| MLKEM768 | 513（0x0201） | 纯抗量子 ML-KEM-768，192 比特 | 同上 |
| MLKEM1024 | 514（0x0202） | 纯抗量子 ML-KEM-1024，256 比特 | 同上 |
| SecP256r1MLKEM768 | 4587（0x11EB） | secp256r1 + ML-KEM-768，192 比特 | RFC 10024 |
| **X25519MLKEM768** | **4588（0x11EC）** | X25519 + ML-KEM-768，192 比特（IANA 标记 Recommended=Y） | RFC 10024 |
| SecP384r1MLKEM1024 | 4589（0x11ED） | secp384r1 + ML-KEM-1024，256 比特 | RFC 10024 |
| curveSM2MLKEM768 | 4590（0x11EE） | SM2 + ML-KEM-768，192 比特 | 草案 draft-yang-tls-hybrid-sm2-mlkem-03 |
| X25519Kyber768Draft00 | 25497（0x6399） | 标准化前的 Kyber768 实验码点，**已由 RFC 10024 废弃** | RFC 10024 §7.4 |
| SecP256r1Kyber768Draft00 | 25498（0x639A） | 同上，已废弃 | RFC 10024 §7.4 |

长度核对（RFC 10024 §4.1/§4.2/§4.3，可用抓包直接验证）：

| 群 | 客户端 `key_exchange` | 服务端 `key_exchange` | 共享秘密 |
|---|---|---|---|
| X25519MLKEM768 | 1216 = ML-KEM-768 封装公钥 1184 + X25519 32 | 1120 = ML-KEM 密文 1088 + X25519 32 | 64 = ML-KEM 32 + X25519 32 |
| SecP256r1MLKEM768 | 1249 = secp256r1 65 + ML-KEM 1184 | 1153 = secp256r1 65 + ML-KEM 1088 | 64 |
| SecP384r1MLKEM1024 | 1665 = secp384r1 97 + ML-KEM 1568 | 1665 = secp384r1 97 + ML-KEM 1568 | 80 = ECDHE 48 + ML-KEM 32 |

> 注意：`X25519MLKEM768` 的名称顺序与拼接顺序**相反**（实际为 ML-KEM 在前、X25519 在后），
> 这是历史原因造成的，RFC 10024 已明确说明；`SecP256r1MLKEM768`、`SecP384r1MLKEM1024`
> 则是 ECDHE 在前。核对拼接结构时必须按此顺序判断，不能只看组名。

### 5.3 身份认证：抗量子签名算法与码点

| 算法 | TLS SignatureScheme 码点 | 量子安全等级 | X.509 算法标识 |
|---|---|---|---|
| ML-DSA-44 | 0x0904 | 安全类别 2（≥128 比特） | RFC 9881 |
| ML-DSA-65 | 0x0905 | 安全类别 3（192 比特） | RFC 9881 |
| ML-DSA-87 | 0x0906 | 安全类别 5（256 比特） | RFC 9881 |
| SLH-DSA-SHA2/SHAKE 128s/128f | 0x0911–0x0912、0x0917–0x0918 | 128 比特 | RFC 9909 |
| SLH-DSA-SHA2/SHAKE 192s/192f | 0x0913–0x0914、0x0919–0x091A | 192 比特 | RFC 9909 |
| SLH-DSA-SHA2/SHAKE 256s/256f | 0x0915–0x0916、0x091B–0x091C | 256 比特 | RFC 9909 |

（ML-DSA 在 TLS 中的码点由 IANA 按 `RFC-ietf-tls-mldsa` 登记；SLH-DSA 在 TLS 中的码点见
`draft-reddy-tls-slhdsa`。Falcon 尚在标准推进过程中，对应的 FIPS 206 尚未发布，故本文不列为
可选实例。）

### 5.4 私用码点与工程实现约定

- TLS Supported Groups 注册表中 **65024–65279（0xFE00–0xFEFF）为 Private Use**，
  TLS SignatureScheme 注册表中 **0xFE00–0xFFFF 为 Private Use**（RFC 9846）。
  在尚无 IANA 码点的算法（如 HQC）以及本课题自定义的混合组合上，工程实现使用该私用段，
  不与标准码点冲突。
- 本课题 TLS 侧已实现并逐条实测的密钥交换组合（含每个组合的 key_share 长度，均按
  "经典分量拼接抗量子分量、不带长度字段"实现，与 RFC 9954 §3.2/§3.3 一致）：

  | 组合 | 码点 | 量子安全等级 | ClientHello / ServerHello 的 key_share 长度（字节） |
  |---|---|---|---|
  | SM2Kyber512Draft00 | 0xfe34（私用） | 128 比特 | 865 / 897 |
  | X25519Kyber512Draft00 | 0xfe30（私用） | 128 比特 | 832 / 800 |
  | X25519Kyber768Draft00 | 0x6399（RFC 10024 已废弃码点） | 192 比特 | 1216 / 1120 |
  | X25519Kyber1024Draft00 | 0xfe36（私用） | 256 比特 | 1600 / 1600 |
  | SM2Kyber1024Draft00 | 0xfe37（私用） | 256 比特 | 1633 / 1697 |
  | X25519HQC-128 | 0xfe38（私用） | 128 比特 | 2281 / 4465 |
  | X25519HQC-256 | 0xfe39（私用） | 256 比特 | 7277 / 14453 |

  其中 HQC 由 liboqs 提供（HQC-128 公钥 2249 / 密文 4433 字节，HQC-256 公钥 7245 / 密文 14421
  字节，与上表拼接后的长度一致）。
- 本课题证书侧已实现并验证的抗量子签名链包括：ML-DSA-44/65/87、SLH-DSA-SHA2-128s/192f/256s、
  以及"SM2 + ML-DSA-87"等双重签名组合，对应 TLS-1-x/3-x 系列测试用例（见
  `docs/测试大纲-输入及操作-细化.md`）；签名与密钥交换的长度、协商结果均可由抓包脚本
  `tools/tls_hello_check.py` 直接断言。

## 6. 参考

- RFC 9846 TLS 1.3：<https://www.rfc-editor.org/rfc/rfc9846.txt>
- RFC 9954 Hybrid Key Exchange in TLS 1.3：<https://www.rfc-editor.org/rfc/rfc9954.txt>
- RFC 10024 PQ/T Hybrid Key Agreement Mechanisms for TLS 1.3：<https://www.rfc-editor.org/rfc/rfc10024.txt>
- RFC 9794 Terminology for PQ/T Hybrid Schemes：<https://www.rfc-editor.org/info/rfc9794>
- IANA TLS Supported Groups：<https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv>
- IANA TLS SignatureScheme：<https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv>
- RFC 9881 ML-DSA in X.509：<https://www.rfc-editor.org/info/rfc9881>
- RFC 9909 SLH-DSA in X.509：<https://www.rfc-editor.org/info/rfc9909>
- FIPS 203（ML-KEM）、FIPS 204（ML-DSA）、FIPS 205（SLH-DSA）：<https://csrc.nist.gov/pubs/fips/203/final>
- NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption（2025-03）：
  <https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption>
