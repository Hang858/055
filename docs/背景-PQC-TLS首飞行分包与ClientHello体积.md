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
| **1455 字节** | 单个 TCP 段能装下的 **TLS 记录长度上限**（MSS 1460 − TLS 记录头 5），超过就会分包 | — |
| ~14.6 KB | **初始拥塞窗口 IW10**（RFC 6928 建议 10×MSS）：它决定"不用等 ACK 能连续发多少"，**不决定是否分包** | RFC 6928 |
| **1200 字节** | QUIC 初始数据报的最小长度（客户端必须填充到至少 1200 字节）；DTLS 1.3 也以约 1200 字节作为"装进一个数据报"的目标 | RFC 9000 §14.1、RFC 9147 |
| 800 / 1184 / 1568 字节 | ML-KEM-512 / 768 / 1024 的**封装公钥**长度，也就是客户端 key_share 中的抗量子分量 | FIPS 203 |
| 32 / 1088 / 1568 字节 | 上面三个参数集对应的**封装密文**长度（服务端 key_share 中的抗量子分量） | FIPS 203 |
| 2249 / 7245 字节 | HQC-128 / HQC-256 的封装公钥长度 | HQC 规范 |

因此：**"600 字节"不是协议规定的包大小上限，也不是某个 KEM 的参数**。它最可能是两种记忆之一：
一是 **IPv4 最小 MTU 576 字节（≈600）**这个经典下限值；二是**传统 ClientHello 本身体积约几百字节
（约 600 字节）**，加上抗量子 key_share（800~2400 字节）后必然翻倍甚至到 2~3 KB。真正可用的判据是：
**"ClientHello 的记录长度能否装进 1 个 MSS / 1 个数据报"**。

## 三、抗量子 KEM 为什么正好顶在这条线上

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

这解释了一个常见现象：**为什么 IETF 推荐的首个 PQ/T 混合组是 X25519**MLKEM768（key_share 1216 字节），
而不是更"安全余量更大"的 ML-KEM-1024 混合组——**1216 + 约 190 ≈ 1406 字节刚好能装进一个以太网报文**；
换成 ML-KEM-1024（1568）就会分包。这就是"抗量子算法选型要同时考虑体积"的由来。

## 四、工程上的应对手段

一是 **key_share 预测**（只发最可能被服务端选中的 1~2 个 key_share，见 IETF 草案
draft-ietf-tls-key-share-prediction），代价是预测失败时服务端回 HelloRetryRequest，多一个 RTT；
二是**服务端引导**，服务端可通过 HelloRetryRequest 要求客户端改用更小的组；
三是**限制并发 key_share 数量**，客户端同时提供多个抗量子组会让首飞行成倍增大；
四是 **DTLS/QUIC 场景必须控制体积**（单数据报 ≤1200 字节量级），或者等待公钥压缩类标准成熟；
五是**基础设施侧适配**，负载均衡、WAF、抓包与日志系统要能正确处理 2~3 KB 甚至更大的 ClientHello
（这正是 Chrome 发布说明提示的中间盒问题）。

## 五、一句话总结

"ClientHello 不要分包"的实质是**控制首飞行报文的体积**：以太网链路上应使 TLS 记录 ≤ 1 个 MSS
（≈1455 字节，对应 key_share ≲1.2 KB），QUIC/DTLS 上应 ≤ 1 个约 1200 字节的数据报；抗量子 KEM 的
公钥/密文是主要占用者。常被记起的"600 字节"并非协议规定值，最可能是 IPv4 最小 MTU 576 字节，
或传统 ClientHello 自身的几百字节体积。

参考：RFC 791（IPv4 最小 MTU 576）、RFC 1122（默认 MSS 536）、RFC 6928（初始拥塞窗口 IW10）、
RFC 9000 §14.1（QUIC 初始数据报 ≥1200 字节）、RFC 9147（DTLS 1.3）、RFC 9954 §4（抗量子公钥
可能使 ClientHello 大于单个报文）、FIPS 203（ML-KEM 参数集）、
[Chrome 发布说明（Kyber 与中间盒兼容性）](https://support.google.com/chrome/a/answer/10314655?hl=en)、
[draft-ietf-tls-key-share-prediction](https://datatracker.ietf.org/doc/draft-davidben-tls-key-share-prediction/)。
