# pqc：C 算法注册机制

`pqc` 是 BiT 和后续多个 C 语言 KEM 的统一入口。目标不是再写一套 Go 算法实现，
而是把 C 算法放进一张注册表，Go/TLS 只通过算法名查找，不写 `switch BiT`。

当前状态：

- **ML-KEM 已接入**：Go 标准库 `crypto/mlkem` 作为 Go 后端注册 `ML-KEM-768/1024`，
  `myx509` 通过证书 `.1.4` OID 查找，TLS KEX/ServerKeyGen 通过 `KEMTLSKEXAlg` 选择；
- **C 注册表仍保留**：`BiT` 是签名占位符，`KEM-TEMPLATE` 是 KEM 占位符；
  `PLACEHOLDER-SIG` / `PLACEHOLDER-KEM` 仅用于测试，不是密码学算法；
- KEM 共享秘密已进入 AHS 两阶段密钥调度（见 `docs/AHS两阶段密钥调度-20261120.md`）；
- 签名路径仍走 `myx509` 的 Dilithium/SLH-DSA 分支，BiT 签名尚未实现。

## 快速验证

```sh
cd pqc
make test
go run ./cmd/pqclist
```

输出应包含：

```text
BiT              1     0xfe20  1.3.6.1.4.1.54321.22.1  placeholder  false
KEM-TEMPLATE     2     0x0000  1.3.6.1.4.1.54321.22.2  placeholder  false
PLACEHOLDER-SIG  1     0xfe7f  1.3.6.1.4.1.54321.99.1  toy-1        true
PLACEHOLDER-KEM  2     0x0000  1.3.6.1.4.1.54321.99.2  toy-1        true
ML-KEM-768       2     0x0000  2.16.840.1.101.3.4.4.2  FIPS 203     true
ML-KEM-1024      2     0x0000  2.16.840.1.101.3.4.4.3  FIPS 203     true
```

## 目录

```text
pqc/
├── include/pq_alg.h          # 唯一 C ABI
├── pq_registry.c             # 注册表、查找、动态注册
├── pq_placeholder.c          # 仅测试用玩具签名/KEM
├── pq_bit_placeholder.c      # BiT / KEM-TEMPLATE 占位描述符
├── pqc.go                    # 唯一 Go 入口：Lookup / All / ByTLSCode
├── mlkem.go                  # Go 标准库 ML-KEM-768/1024 后端
├── pqc_test.go               # 注册表、签名、KEM、cgo 边界
├── mlkem_test.go             # ML-KEM 往返、OID、公钥派生
├── cmd/pqclist/main.go       # 列出注册表
├── cmd/pqkemkey/main.go      # 生成 KEM 原始密钥
└── Makefile                  # 静态库 + go test
```

## C 入口

```c
const pq_alg *pq_alg_lookup(const char *name);
const pq_alg *pq_alg_by_tls_code(uint16_t code);
const pq_alg *pq_alg_at(size_t index);
size_t        pq_alg_count(void);
```

一张表同时管签名和 KEM，靠 `pq_alg.kind` 区分：

- `PQ_KIND_SIG`：`keygen / pub_from_sk / sign / verify`
- `PQ_KIND_KEM`：`keygen / pub_from_sk / encaps / decaps`

注册是**链接期静态注册**：在 `pq_registry.c` 的 `pq_builtin[]` 里加一行指向算法描述符。
不推荐 `__attribute__((constructor))`，因为静态链接时可能被丢弃，也不利于审计。
插件场景可以在服务启动前调用 `pq_alg_register()`；该函数不是线程安全的，握手期间不要调用。

## 签名输入：与现有项目对齐

当前 TLS 栈给 PQ 算法的是 **SHA-512 摘要**，不是原始握手消息：

```text
signedMessage = SHA512(64×0x20 || context(含结尾 0x00) || transcript_hash)
QuantumSignWithLocalKeyAlg(signedMessage, ...)
```

因此 C 签名适配器必须：

- 描述符里写 `input = PQ_INPUT_DIGEST`；
- `sign()` 直接对传入的 `msg` 签名，**不要再做一次哈希**；
- 如果 C 库只有 `sign(message)` 且内部会哈希，必须用它提供的“签摘要”接口，
  或在适配器里明确禁止二次哈希。

`PLACEHOLDER-SIG` 演示了这条语义：测试里传 64 字节 digest，`Sign/Verify` 都把它当消息本身。

## 加 BiT：只写一个 C 文件

1. 实现 C 函数，填入 `pq_alg`：

```c
static int bit_keygen(uint8_t *pk, uint8_t *sk);
static int bit_pub_from_sk(const uint8_t *sk, uint8_t *pk);
static int bit_sign(const uint8_t *sk, const uint8_t *msg, size_t msg_len,
                    uint8_t *sig, size_t sig_cap);
static int bit_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig, size_t sig_len);

const pq_alg pq_bit = {
    .abi_version = PQ_ALG_ABI_VERSION,
    .kind = PQ_KIND_SIG,
    .input = PQ_INPUT_DIGEST,
    .name = "BiT",
    .oid = "1.3.6.1.4.1.54321.22.1",  /* TODO: confirm */
    .tls_code = 0xFE20,               /* TODO: confirm */
    .version = "bit-1.0",
    .pk_len = ..., .sk_len = ..., .sig_len = ...,
    .keygen = bit_keygen,
    .pub_from_sk = bit_pub_from_sk,
    .sign = bit_sign,
    .verify = bit_verify,
};
```

2. 把 `pq_bit_placeholder.c` 里的 `pq_bit` 占位符换成上面的真实描述符（或删除该占位文件、新增 `bit_sig.c`）；
3. 在 `pq_registry.c` 的 `pq_builtin[]` 里保留 `&pq_bit`；
4. 重跑 `make test` 和 `go run ./cmd/pqclist`。

**Go/TLS 不需要知道 BiT。** Go 侧只调用 `Lookup("BiT")`。

## 加 KEM

同一个注册表，换 `kind` 和函数指针：

```c
const pq_alg pq_kem_x = {
    .abi_version = PQ_ALG_ABI_VERSION,
    .kind = PQ_KIND_KEM,
    .name = "KEM-X",
    .oid = "1.3.6.1.4.1.54321.22.3",
    .tls_code = 0,                 /* KEM 不进 SignatureScheme */
    .pk_len = ..., .sk_len = ...,
    .ct_len = ..., .ss_len = ...,
    .keygen = kem_keygen,
    .pub_from_sk = kem_pub_from_sk,
    .encaps = kem_encaps,
    .decaps = kem_decaps,
};
```

`pqc.Lookup("KEM-X")` 后调用 `Encapsulate/Decapsulate`。KEM 不经过 CertificateVerify，
所以不要给它分配 TLS SignatureScheme 码点。

## Go 上层用法

```go
alg, err := pqc.Lookup("BiT")
if err != nil { ... }
if !alg.Available() { ... }   // 占位符/未链接

kp, err := alg.GenerateKey()
sig, err := alg.Sign(kp.Private, digest)   // digest 由 TLS 提供
err = alg.Verify(kp.Public, digest, sig)
```

上层代码没有 `if BiT`，换算法只改 `Lookup` 的参数/配置。

## 接进现有 TLS 的位置

KEM 路径已经按下面接好：

1. `pqc` 的 C/Go 文件复制到补丁 GOROOT 的 `src/crypto/pq/`，包名改为 `pq`；
2. `crypto/myx509` 增加 `.1.4` KEM 算法 OID 读取、`KEMAlgorithmFromCert`、
   `QuantumDecryptionWithLocalKeyAlg`；`EncryptionFromCert` 优先按 `.1.4` 查 `pq.Lookup`，
   没有 `.1.4` 时保持 Kyber768 旧行为；
3. `crypto/tls/common.go` 增加 `KEMTLSKEMAlg/KEMTLSKEMKey`；
   server/client 的 KEM 证书路径使用这两个字段，缺密钥/坏密文返回 alert 而不是忽略；
4. 证书工具用 `.1.0` 放 KEM 公钥，`.1.4` 放 KEM 算法 OID；
5. 测试：`ProtocolType=21` + `PLACEHOLDER-KEM` 的 1 次握手通过；缺 KEM 私钥、坏长度、错误 KEM 私钥都会失败（错误私钥在 client Finished 处被拒绝）。KEM SS 还没有进入 key schedule，应用数据密钥仍来自 ECDHE。

签名 BiT 还需要一次性把 `crypto/myx509` 的 `pqSignWithAlg/pqVerifyWithAlg` 的
`switch` 改成 `pq.Lookup`，并给 TLS 增加 BiT 码点；KEM 的接入不妨碍这一步。

KEM 的安全边界仍然不变：**共享密钥没有进入 `key_schedule`**，KEM 证书模式目前仍是
RSA 认证 + 通用 KEM 密文交换，不能称为完整的 KEMTLS 抗量子认证。

## 静态库与动态库

- 生产推荐静态链接：`make lib` 生成 `lib/libpqalg.a`，和 Go 程序一起链接；
- `.so` 插件：导出 `pq_plugin_init`，服务启动前 `dlopen` + `pq_alg_register`；
  需要处理路径、版本、符号冲突和崩溃隔离，不建议用于默认交付；
- 不建议用“命令行子进程签名”：握手延迟、密钥传递和进程隔离都不合适。

## 安全边界

`PLACEHOLDER-SIG` / `PLACEHOLDER-KEM` 是**玩具算法**，只用于验证注册表和 cgo 边界，
不能用于任何真实连接。`BiT` 描述符的 OID `1.3.6.1.4.1.54321.22.1` 和 TLS 码点 `0xFE20`
也是占位值，正式启用前必须确认企业 OID 和私有码点，避免与现有/未来算法冲突。

## 新增 KEM 的接口

后续新增 C KEM 不需要改 TLS：

1. 实现 `pq_alg` 的 `keygen / pub_from_sk / encaps / decaps`；
2. 在 `pq_registry.c` 的 `pq_builtin[]` 添加描述符，或启动前
   `pq_alg_register()`；
3. TLS 用 `KEMTLS_KEX_ALG` 选 KEX/ServerKeyGen，用 `KEMTLS_KEM_ALG` +
   证书 `.1.4` OID 选 KEM 证书。

`crypto/tls/pq_kex.go` 已改为通过 `crypto/pq` 查找算法，只有 Kyber768 保留
旧 CIRCL 兼容分支。`PLACEHOLDER-KEM` 已作为纯 C 注册表样例跑通 ServerKeyGen。

详见 `docs/KEM接入接口-20261122.md`。
