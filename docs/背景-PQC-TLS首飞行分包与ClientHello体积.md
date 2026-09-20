# 背景知识：抗量子 TLS 握手中「ClientHello 首包不要分包」的要求

> 说明：本文属于通用背景知识（不属于本课题的 TLS 实现），用于解释"抗量子 KEM 会让 TLS 的第一个
> 交互包变大、最好不分包"这条要求的来龙去脉，以及常见数字（包括常被记成"600 字节"的那个数）
> 到底指什么。

## 一、这条要求指的是什么

TLS 握手的第一个报文是客户端发出的 **ClientHello**（携带 supported_groups、key_share、
signature_algorithms 等扩展），它是整个握手的"首飞行"（first flight）。工程上要求它**尽量装进
一个 TCP 段（或一个数据报），不要跨段/分包**，原因是：

1. **丢包代价放大**：ClientHello 一旦被拆成多个 TCP 段，其中任何一段丢失都要重传，握手至少多花
   一个往返（RTT）。抗量子公钥很大，首飞行本来就只有 1~2 个报文，重传代价相对更明显。
2. **中间盒/负载均衡的兼容性**：防火墙、NAT、LB、IDS 等设备对"跨段的 ClientHello"处理策略不一致，
   有的只解析第一个 TCP 段、有的对超大 ClientHello 直接拒绝。这一点有真实案例——Chrome 启用
   Kyber 时的发布说明就明确提示：*"some TLS middleboxes might be unprepared for the size of a
   Kyber (ML-KEM) key encapsulation… resulting in broken or hung connections"*（部分 TLS 中间盒
   无法处理 Kyber/ML-KEM 密钥封装的体积，会导致连接中断或挂起）。
3. **DTLS / QUIC 是硬约束**：DTLS 的握手报文必须放在单个数据报里；QUIC 规定客户端必须把承载
   Initial 包的数据报**填充到至少 1200 字节**（RFC 9000 §14.1）。也就是说在 QUIC/DTLS 上
   ClientHello 不能"跨包"，抗量子公钥一大就会顶破单个数据报的容量。
4. **规范本身并不禁止分包**：TLS 记录层允许 ClientHello 跨多条记录，TCP 也会自动重组；RFC 9954
   §4 也承认抗量子算法"may result in ClientHello messages larger than a single packet"。
   所以"不要分包"是**部署层/性能层的最佳实践**，不是协议强制条款；能控制的是"客户端发几个
   key_share、发多大的组"，而不是改协议。

## 二、相关数字分别是什么（含"600 字节"的澄清）

| 数字 | 含义 | 出处 |
|---|---|---|
| **576 字节** | IPv4 的**最小重组缓冲区 / 最小 MTU**：任何链路都必须能转发 576 字节的报文而不再分片；对应 TCP 未协商时的默认 MSS 536 字节 | RFC 791、RFC 1122 §4.2.3.1 |
| ~600 字节 | **传统（不含抗量子份额）ClientHello 的典型体积**：只有 X25519 等经典 key_share 时，ClientHello 的 TLS 记录长度通常在几百字节量级 | 实测经验值 |
| **1460 字节** | 以太网 MTU 1500 下的 TCP **MSS**（1500 − IPv4 头 20 − TCP 头 20） | — |
| **1455 字节** | 单个 TCP 段能装下的 **ClientHello 记录长度字段上限**（= MSS 1460 − TLS 记录头 5）。注意：抓包/解析脚本打印的"记录长度"指的是**记录头里的 length 字段**，它不含 5 字节记录头；在线字节数 = 该值 + 5。若链路启用 TCP 时间戳（Linux 默认），实际单段容量约再减 12 字节（≈1443） | — |
| ~14.6 KB | **初始拥塞窗口 IW10**（RFC 6928 建议 10×MSS）：它决定"不用等 ACK 能连续发多少"，**不决定是否分包** | RFC 6928 |
| **1200 字节** | QUIC 初始数据报的最小长度（客户端必须填充到至少 1200 字节）；DTLS 1.3 也以约 1200 字节作为"装进一个数据报"的目标 | RFC 9000 §14.1、RFC 9147 |
| 800 / 1184 / 1568 字节 | ML-KEM-512 / 768 / 1024 的**封装公钥**长度，也就是客户端 key_share 中的抗量子分量 | FIPS 203 |
| 32 / 1088 / 1568 字节 | 上面三个参数集对应的**封装密文**长度（服务端 key_share 中的抗量子分量） | FIPS 203 |
| 2249 / 7245 字节 | HQC-128 / HQC-256 的封装公钥长度 | HQC 规范 |

因此：**"600 字节"不是协议规定的包大小上限，也不是某个 KEM 的参数**。它最可能是两种记忆之一：
一是 **IPv4 最小 MTU 576 字节（≈600）**这个经典下限值；二是**传统 ClientHello 本身体积约几百字节
（约 600 字节）**，加上抗量子 key_share（800~2400 字节）后必然翻倍甚至到 2~3 KB。真正可用的判据是：
**"ClientHello 的记录长度能否装进 1 个 MSS / 1 个数据报"**。

## 三、ClientHello 的"其余开销"有多少、是否固定（实测拆解）

**先说明为什么这里出现 X25519**：X25519 本身就是 TLS 1.3 的密钥交换组（RFC 9846 的 `x25519`，IANA 码点 29），也是标准混合组 `X25519MLKEM768` 的经典分量；本节把它当作"尺子"做基线测量——因为它的 key_share 只有 32 字节，用它抓到的 ClientHello 长度减去 32，就得到"除密钥以外的开销"。

**结论：不固定。** 它是"某个具体客户端"实现的扩展集合，随客户端、域名长度、算法列表长度而变化。
本仓库客户端（Go 实现，无 ALPN、无 GREASE、无 padding）的实测拆解如下，两个极端配置各测一次：

| 组成 | 基线对照组：X25519-only（1 个 supported_group、key_share 仅 32 字节，**仅用于量出"除密钥以外的开销"，不参与任何指标结论**） | 默认配置（6 个 supported_groups，key_share 865 字节） |
|---|---|---|
| TLS 记录头 | 5 | 5 |
| 握手头（类型 + 3 字节长度） | 4 | 4 |
| legacy_version | 2 | 2 |
| random | 32 | 32 |
| session_id（长度字段 1 + 32 字节） | 33 | 33 |
| cipher_suites（长度字段 2 + 3 个套件×2） | 8 | 8 |
| compression_methods | 2 | 2 |
| extensions 总长字段 | 2 | 2 |
| server_name(SNI, "localhost") | 18 | 18 |
| status_request | 9 | 9 |
| supported_groups（**每组 2 字节**） | 8（1 组） | 18（6 组） |
| ec_point_formats | 6 | 6 |
| signature_algorithms | 30 | 30 |
| renegotiation_info | 5 | 5 |
| extended_master_secret | 4 | 4 |
| SCT | 4 | 4 |
| supported_versions | 7 | 7 |
| key_share 框架（扩展头 4 + 列表长度 2 + 条目头 4） | 10 | 10 |
| key_share 密钥字节 | 32 | 865（SM2Kyber512） |
| **在线合计（字节）** | **221** | **1064** |
| **除密钥字节外的开销** | **189** | **199** |

由此得到可直接用于估算的公式：

```
ClientHello 在线字节数 ≈ key_share 密钥字节数 + 其他开销（本客户端 189~199 字节）
```

其他开销会随下列因素变化：支持的组数（每个 2 字节）、SNI 主机名长度（每字符 1 字节）、
cipher_suites 个数（每个 2 字节）、signature_algorithms 个数（每个 2 字节）、是否发送多个
key_share（每多一个增加 4 + 该组公钥长度）、是否带 ALPN / psk_key_exchange_modes / padding /
ECH / GREASE 等扩展（浏览器通常比上表多 100~200 字节，实际开销约 300~400 字节）。
**因此定指标时应以"目标客户端 + 实测"为准，不要假设一个固定开销值。**

## 四、抗量子 KEM 为什么正好顶在这条线上

在只发一个 key_share 的情况下，ClientHello 的 TLS 记录长度 ≈ **抗量子 key_share 长度 + 约 190 字节**
（其余固定扩展与开销）。按以太网 MSS 1455 字节反推，**key_share 的安全上限约 1.26 KB**：

| 组合 | key_share（客户端，字节） | ClientHello 记录长度（实测，字节） | 是否单段（以太网 MSS 1455） |
|---|---|---|---|
| SM2Kyber512Draft00 | 865 | **1059** | ✅ 单段 |
| X25519MLKEM768（标准推荐组，RFC 10024） | 1216 | 约 1406 | ✅ 勉强单段 |
| X25519Kyber1024Draft00 | 1600 | **1784** | ❌ 两段 |
| X25519HQC-128 | 2281 | **2465** | ❌ 两段 |
| X25519HQC-256 | 7257（32+7245） | 约 7450 | ❌ 多段 |

（上表中间三行的实测值取自本仓库抓包，可用 `python3 tools/tls_hello_check.py <pcap>` 复核；
"约 1406""约 7450"为按 "+190 字节"规律推算。）

**Kyber-768 / Kyber-1024 是不是"一定分包"？** 不是绝对的，取决于 (key_share 长度 + 该客户端其他开销)
与路径 MSS 的比较：

- Kyber-768/ML-KEM-768（key_share 1184 字节）：在本仓库客户端下 ClientHello = 1184 + 199 = 1383（在线 1388），
  小于以太网 MSS 1460，**标准以太网上不分包**；但在浏览器式客户端（其他开销 300~400）下约 1484~1584，
  会超过 1460 而**分包**；在 MTU 1400 的隧道上（MSS 1360）也会分包；在 QUIC/DTLS 的 1200 字节
  单数据报下必然放不下。
- Kyber-1024/ML-KEM-1024（key_share 1568 字节）：即使把其他开销压到理论最小（仅保留
  supported_versions、supported_groups、signature_algorithms 与 key_share，约 84 字节），
  ClientHello 也约 1652 字节 > 1460，**在以太网及更小 MTU 的链路上必然分包**（只有 MTU ≥1812
  的巨型帧才可能单段）；用本仓库客户端实测为 1767（在线 1772）。

这解释了一个常见现象：**为什么 IETF 推荐的首个 PQ/T 混合组是 X25519**MLKEM768（key_share 1216 字节），
而不是更"安全余量更大"的 ML-KEM-1024 混合组——**1216 + 约 190 ≈ 1406 字节刚好能装进一个以太网报文**；
换成 ML-KEM-1024（1568）就会分包。这就是"抗量子算法选型要同时考虑体积"的由来。

## 五、工程上的应对手段

一是 **key_share 预测**（只发最可能被服务端选中的 1~2 个 key_share，见 IETF 草案
draft-ietf-tls-key-share-prediction），代价是预测失败时服务端回 HelloRetryRequest，多一个 RTT；
二是**服务端引导**，服务端可通过 HelloRetryRequest 要求客户端改用更小的组；
三是**限制并发 key_share 数量**，客户端同时提供多个抗量子组会让首飞行成倍增大；
四是 **DTLS/QUIC 场景必须控制体积**（单数据报 ≤1200 字节量级），或者等待公钥压缩类标准成熟；
五是**基础设施侧适配**，负载均衡、WAF、抓包与日志系统要能正确处理 2~3 KB 甚至更大的 ClientHello
（这正是 Chrome 发布说明提示的中间盒问题）。

## 六、一句话总结

"ClientHello 不要分包"的实质是**控制首飞行报文的体积**：以太网链路上应使 TLS 记录 ≤ 1 个 MSS
（记录长度字段 ≤1455 字节、在线 ≤1460 字节，对应 key_share ≲1.25 KB），QUIC/DTLS 上应 ≤ 1 个约 1200 字节的数据报；抗量子 KEM 的
公钥/密文是主要占用者。常被记起的"600 字节"并非协议规定值，最可能是 IPv4 最小 MTU 576 字节，
或传统 ClientHello 自身的几百字节体积。

参考：RFC 791（IPv4 最小 MTU 576）、RFC 1122（默认 MSS 536）、RFC 6928（初始拥塞窗口 IW10）、
RFC 9000 §14.1（QUIC 初始数据报 ≥1200 字节）、RFC 9147（DTLS 1.3）、RFC 9954 §4（抗量子公钥
可能使 ClientHello 大于单个报文）、FIPS 203（ML-KEM 参数集）、
[Chrome 发布说明（Kyber 与中间盒兼容性）](https://support.google.com/chrome/a/answer/10314655?hl=en)、
[draft-ietf-tls-key-share-prediction](https://datatracker.ietf.org/doc/draft-davidben-tls-key-share-prediction/)。
