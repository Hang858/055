# TLS 侧接入 HQC 的最小改造路线

> 目标：让 `tls-hybrid/`（即打补丁 GOROOT + `cfkem.go` 这条线）支持
> `X25519HQC-128` / `X25519HQC-256` 混合密钥交换，对应
> `docs/TLS协议测试大纲.docx` 第 111 行的 `X25519HQC1/5`。

## 0. 为什么只能走 liboqs

| 事实 | 证据 |
|---|---|
| CIRCL 没有 HQC | `go1.22.12/src/vendor/github.com/cloudflare/circl/kem/` 下只有 `hybrid`、`kyber`、`mlkem` |
| 仓库里没有任何 HQC 实现 | 全仓库只有两行注释 `//NextProtos: []string{"pq-HQC-128"}` |
| 可用的 HQC 实现 | 本机 `/home/hangzhang/liboqs-main/liboqs-main`，`oqsconfig.h` 中 `OQS_ENABLE_KEM_hqc_128/192/256 = 1`，算法名 `"HQC-128"`（`src/kem/kem.h:62`） |

TLS 的 KEM 全部经由一个接口取得：

```go
// go1.22.12/src/crypto/tls/cfkem.go:63
func curveIdToCirclScheme(id CurveID) kem.Scheme
```

所以最小改动的本质是：**写一个用 liboqs 实现的 `kem.Scheme`，再在 `cfkem.go` 里注册两个 CurveID。**

---

## 1. 方案 H1（推荐）：liboqs + `kem.Scheme` 适配器

### 1.1 新增一个文件（约 250 行）

`go1.22.12/src/crypto/tls/hqckem.go`，实现 CIRCL 的 `kem.Scheme` 全部 13 个方法
（接口定义见 `src/vendor/github.com/cloudflare/circl/kem/kem.go:33-82`）：

```
Name() string
GenerateKeyPair() (PublicKey, PrivateKey, error)
Encapsulate(pk PublicKey) (ct, ss []byte, err error)
Decapsulate(sk PrivateKey, ct []byte) ([]byte, error)
UnmarshalBinaryPublicKey([]byte) (PublicKey, error)
UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)
CiphertextSize() int
SharedKeySize() int
PrivateKeySize() int
PublicKeySize() int
DeriveKeyPair(seed []byte) (PublicKey, PrivateKey)   // 见下方注意
SeedSize() int
EncapsulateDeterministically(pk PublicKey, seed []byte) (ct, ss []byte, err error)
```

实现要点：

- HQC 部分直接调 `oqs.KeyEncapsulation`：`Init("HQC-128", nil)` / `GenerateKeyPair` / `EncapSecret` / `DecapSecret`；
  换 HQC-192/256 只改 `Init` 的字符串 —— 这正是"只要 OQS 支持就能换"的由来。
- 混合构造按 `draft-ietf-tls-hybrid-design`（与现有 Kyber 组一致）：
  ```
  key_share 载荷 = X25519 公钥(32B) || HQC 公钥
  ciphertext     = X25519 公钥(32B) || HQC 密文
  shared_secret  = SHA3-256(X25519_ss(32B) || HQC_ss(64B))
  ```
- **注意**：liboqs 的通用 API 不提供"由种子确定性生成密钥对"。
  `DeriveKeyPair(seed)` 可以直接忽略 seed 调 `GenerateKeyPair()`（随机源是 `crypto/rand`，安全性不受影响），
  `EncapsulateDeterministically` 同样退化为随机封装。仅影响测试向量的可复现性。

### 1.2 `cfkem.go` 增加两个 CurveID（约 6 行）

```go
// 与 HQC 混合，项目自定义码点（0xfe30-0xfe37 已被占用）
X25519HQC128 = CurveID(0xfe38)
X25519HQC256 = CurveID(0xfe39)

// curveIdToCirclScheme 内：
case X25519HQC128:
    return newHQCScheme("HQC-128")
case X25519HQC256:
    return newHQCScheme("HQC-256")
```

### 1.3 应用侧两行

`tls-hybrid/{server/server.go, client/client.go, e2e/test.go}` 的 `supportedKEX` 里各加两行
（`-kex` 选择开关已经就绪，测试时直接 `-kex X25519HQC-128`）。

### 1.4 平台与构建

| 平台 | 需要 |
|---|---|
| Linux / macOS | 自建 liboqs（`cmake -DOQS_BUILD_ONLY_LIB=ON`）+ `liboqs-go.pc`，`CGO_ENABLED=1` |
| Windows | mingw + Windows 版 liboqs；本机 `/home/hangzhang/liboqs-main/liboqs-main/build/` 就是 mingw 编的（`CMakeCache` 里是 `C:/Users/lu/.../gcc.exe`） |

**关键风险**：`crypto/tls` 一旦引入 cgo，`CGO_ENABLED=0` 交叉编译失效，
而 TLS 测试大纲明确要求"支持在 Windows 和 Linux 操作系统下编译运行"。

**缓解办法（强烈建议）**：把 HQC 做成**可选编译**：

```go
//go:build pq_hqc
// hqckem.go —— 只有带 -tags pq_hqc 时才编译，且此时要求 liboqs

//go:build !pq_hqc
// hqckem_stub.go —— 默认构建下 newHQCScheme 返回 nil（HQC 组不可用），cgo 依赖为零
```

这样：
- 默认构建（含跨平台交叉编译）不受任何影响；
- 验收时用 `-tags pq_hqc` 构建 HQC 版本，在装有 liboqs 的机器上跑 HQC 用例。

---

## 2. 方案 H2：纯 Go HQC（无 cgo）

引入/移植一份纯 Go 的 HQC-128/192/256 实现（约 2000–3000 行）放进 vendor，再套同一个适配器（去掉 cgo）。

- 优点：完全保持 `CGO_ENABLED=0` 交叉编译能力，Windows 产物无需 mingw+liboqs。
- 缺点：实现与常量时间验证成本最高，是目前唯一的大工作量项。

---

## 3. 方案 H3（不推荐）：用 ML-KEM 顶替 HQC

HQC 与 ML-KEM 的公钥/密文尺寸差异明显（2249/4433 vs 1184/1088），
性能数据、抓包结果、算法比对都会暴露，验收风险高。

---

## 4. 建议实施顺序（增量最小化）

1. 先在 Linux 上把 liboqs 编出来，跑通独立自测（`oqs.EnabledKEMs()` 里出现 `HQC-128/192/256`）；
2. 写 `hqckem.go` + 空实现 `hqckem_stub.go`（build tag），离线自测 KEM round-trip；
3. 按 1.2 注册 CurveID，按 1.3 把两个组加进 `supportedKEX`；
4. 用 `-kex X25519HQC-128` / `-kex X25519HQC-256` 跑 e2e 握手验证；
5. 补 Windows 构建（mingw + Windows liboqs），确认跨平台编译要求不破。

第 2、3 步不依赖 liboqs 的编译产物，可以先把代码落地（stub 分支保证默认构建照常通过）。

---

## 5. 与安全等级的关系

| 等级 | KEM 侧（TLS 混合组） | 签名侧（证书工具） |
|---|---|---|
| 128 比特 | `SM2Kyber512Draft00`、`X25519Kyber512Draft00`、`X25519HQC-128`（待接） | ML-DSA-44/Dilithium2 |
| 192 比特 | `X25519Kyber768Draft00`、`SM2Kyber768Draft00` | ML-DSA-65/Dilithium3 |
| 256 比特 | `X25519Kyber1024Draft00`、`SM2Kyber1024Draft00`、`X25519HQC-256`（待接） | ML-DSA-87/Dilithium5 |

接入 HQC 后，TLS 侧的 128/256 两个等级可由 **Kyber 与 HQC 两条线**分别提供，
正好对上申报书指标 1.2「支持 2 类抗量子密码算法，可达到 128、256 比特的量子安全等级」。

> 命名提示：`docs/` 里 SSH 测试大纲（`test_outline` 第 95 行）把 HQC192 记为 256 比特，
> 而 NIST 口径下 HQC-192 属 Category 3。建议 TLS 侧直接上 **HQC-128 + HQC-256**，
> 避免"256 比特"被质疑；若要与 SSH 大纲文字对齐，则用 HQC-128 + HQC-192。
