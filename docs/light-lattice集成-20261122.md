# BiT / PolarLAC 下载、编译与 TLS 集成

日期：2026-11-22
来源：<https://light-lattice.org/>

## 1. 下载与版本

| 算法 | 版本 | 包 | SHA256 |
|---|---|---|---|
| BiT | v2.1 / 2026-11-06 | `BiT-20261106.zip` | 本地下载，源码已入库 `pqc/vendor/bit/` |
| PolarLAC | v1.0 / 2026-09-20 | `PolarLAC.zip` | 本地下载，源码已入库 `pqc/vendor/polarlac/` |

BiT 原始包还包含 `BiT-compact`、AVX 和测试程序；仓库保留 BiT 参考实现
`BiT-{128,256,512}` 的源码。PolarLAC 保留 x86 参考实现的五个参数集。

## 2. 编译

```sh
cd pqc/vendor
./build.sh
# 生成 lib/libbit-{128,256,512}.so
#      lib/libpolarlac-{128,256,512,Light,512-Star}.so
```

BiT 全部等级已用官方 `make` 编译通过（ref/avx、BiT/BiT-compact），TLS 适配器
使用 ref 库。PolarLAC 的 Reference/Optimized x86 五个等级也全部编译通过；
适配器使用 Reference 库，默认 `BIT_USE_SHAKE=0`（SM3 后端）。

## 3. 集成方式（与业务代码解耦）

- `pqc/lightlattice.c` 通过 `dlopen` 加载每个 `.so`，用
  `dlsym` 拿 `sig_*` / `kem_*` / DRNG 函数；
- 适配成 `pq_alg` 描述符，注册到 C 注册表；
- TLS 仍只通过 `pq.Lookup`/`ByOID` 使用算法，**不包含 vendor 头文件**；
- 算法更新时只替换 `lib/libbit-*.so` / `lib/libpolarlac-*.so`，TLS 不需要重编；
- `LIGHTLATTICE_LIBDIR` 指定库目录，默认当前目录。

每个 `.so` 独立加载，避免 BiT/PolarLAC 的全局 DRNG 和通用符号名冲突；适配器
对每个库加互斥锁，因为 vendor 实现使用全局 DRNG。

## 4. 算法表

**BiT**（签名，TLS 私有码点）：

| 算法 | pk | sk | sig | TLS code | OID |
|---|---:|---:|---:|---|---|
| BiT-128 | 1264 | 1696 | 1440 | 0xFE30 | 1.3.6.1.4.1.54321.30.1 |
| BiT-256 | 2528 | 3392 | 2976 | 0xFE31 | 1.3.6.1.4.1.54321.30.2 |
| BiT-512 | 5824 | 7488 | 7474 | 0xFE32 | 1.3.6.1.4.1.54321.30.3 |

**PolarLAC**（KEM）：

| 算法 | pk | sk | ct | ss | OID |
|---|---:|---:|---:|---:|---|
| POLARLAC-128 | 530 | 1570 | 640 | 16 | 1.3.6.1.4.1.54321.31.1 |
| POLARLAC-256 | 1060 | 3140 | 1280 | 32 | 1.3.6.1.4.1.54321.31.2 |
| POLARLAC-512 | 2116 | 6276 | 2560 | 64 | 1.3.6.1.4.1.54321.31.3 |
| POLARLAC-Light | 530 | 1570 | 608 | 16 | 1.3.6.1.4.1.54321.31.4 |
| POLARLAC-512-Star | 2522 | 6682 | 2970 | 64 | 1.3.6.1.4.1.54321.31.5 |

OID 和 TLS 码点目前是项目私有值，等厂商给出正式值后只改描述符/映射表。

## 5. TLS 证书与配置

证书工具：

```sh
LIGHTLATTICE_LIBDIR=pqc/vendor/lib .build/lightcert \
  -alg BiT-128 -kem-alg POLARLAC-128 -out /tmp/ll-certs
```

- 叶子证书 `.1.1` = BiT 公钥，`.1.3` = BiT OID；
- 同时带 KEM 时 `.1.0` = PolarLAC 公钥，`.1.4` = PolarLAC OID；
- 证书链仍是 RSA 经典链；`-kem-alg` 可省略。

TLS 环境变量：

```bash
LIGHTLATTICE_LIBDIR=pqc/vendor/lib
KEMTLS_SIG_ALG=BiT-128          # 证书/ CertificateVerify
KEMTLS_SIG_KEY=.../sig.priv
KEMTLS_KEM_ALG=POLARLAC-128     # KEM 证书
KEMTLS_KEM_KEY=.../srv-kem.priv
KEMTLS_KEX_ALG=POLARLAC-128     # 混合 KEX/ServerKeyGen
```

## 6. 实测

| 场景 | 结果 |
|---|---|
| BiT-128/256/512（ProtocolType=11） | 全部 PASS |
| PolarLAC-128/256/512/Light/512-Star KEX（type 13） | 全部 PASS |
| PolarLAC 五个等级 KEM 证书（type 20） | 全部 PASS |
| BiT-128 签名 + PolarLAC-128 Sig-KEM（type 21） | PASS |
| BiT-128 签名 + PolarLAC-128 KEM-Sig（type 11） | PASS |
| `pqc` 单测（BiT 三档、PolarLAC 五档） | PASS |

## 7. 边界

- BiT 的 NGCC API 没有 `pub_from_sk`，注册表对签名算法放宽了该要求；
  证书公钥由 `lightcert` 的 keygen 直接写入。
- PolarLAC 的 `pub_from_sk` 按 `sk = PKE sk || pk || reject_seed(16)` 的布局提取，
  厂商若改变布局需要同步适配器。
- 适配器用互斥锁串行化同一算法的 DRNG；高并发下性能会受限。
- PolarLAC 当前使用 SM3 后端；需要 SHAKE 后端时用
  `make BIT_USE_SHAKE=1` 重编对应 `.so`。
- 没有把 BiT/PolarLAC 的证书链 PQ 双签名接进来；PQ 链验签仍可用但需要
  另行生成双签证书。
- TLS 扩展/消息码点仍是私有，不是 IETF 标准；BiT/PolarLAC 的 OID 也是私有值。
