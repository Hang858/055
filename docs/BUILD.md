# 构建说明

## 环境要求

| 组件 | 需要 | 说明 |
|---|---|---|
| `tls-hybrid/`（混合 TLS 源码库） | **打补丁的 Go 1.22.12** | 系统 Go（如 1.22.2）里没有 `tls.SM2Kyber512Draft00` 等符号，必须用补丁工具链 |
| `pqtls-1.3/`（TLS 1.3 客户端/服务端） | Go 1.22+ | 但当前入口缺少符号，**编译不过**，见「D. 已知问题」 |
| `pqcert/`（抗量子证书生成工具） | Go 1.25+ | 依赖 `github.com/cloudflare/circl v1.6.3` |
| 后续接入 HQC | liboqs + liboqs-go | 见「E. liboqs（HQC 前置条件）」 |

---

## A. 重建打补丁的 Go 1.22.12

仓库里的 `go1.22.12/` 是**本机 macOS/amd64** 版（`bin/go` 是 Mach-O），
在 Linux 上不可执行；Linux 需要按下面步骤自己重建一份。

```sh
# 1. 下载官方源码（也可用镜像 https://mirrors.aliyun.com/golang/go1.22.12.src.tar.gz）
curl -LO https://go.dev/dl/go1.22.12.src.tar.gz
tar xzf go1.22.12.src.tar.gz

# 2. 打补丁（补丁路径为 a/src/... 与 b/src/...，所以用 -p1，在 GOROOT 根目录执行）
cd go
patch -p1 < /path/to/patches/go1.22.12-crypto-tls.patch
patch -p1 < /path/to/patches/go1.22.12-sm2-mldsa-auth.patch
patch -p1 < /path/to/patches/go1.22.12-sm2-mldsa-mtls.patch
patch -p1 < /path/to/patches/go1.22.12-sm2-mlkem.patch

# 3. 放入补丁新增的 CIRCL vendor 树（归档内是 circl/ 目录）
tar xzf /path/to/patches/vendor-circl.tgz -C src/vendor/github.com/cloudflare

# 4. 编译（需要一个 Go 1.20.14+ 的引导工具链）
GOROOT_BOOTSTRAP=/usr/lib/go-1.22 ./src/make.bash

# 5. 之后所有 tls-hybrid 的构建都指定这个 GOROOT
export GOROOT=$PWD
export PATH=$GOROOT/bin:$PATH
go version   # go1.22.12
```

补丁内容与已验证状态见 `../patches/README.md`。

> 注意：`patches/go1.22.12-crypto-tls.patch` 已用 `patch -p1 -R --dry-run` 对
> 仓库里现成的 `go1.22.12/` 反向校验通过，可直接复用。

---

## B. 构建 tls-hybrid（混合 TLS 源码库）

入口文件（`package main`）：

| 程序 | 源文件 | 说明 |
|---|---|---|
| 服务端 | `tls-hybrid/server/server.go` | 监听 `:8080`，`CurvePreferences` 里含 `X25519Kyber512Draft00`/`SM2Kyber512Draft00`/`X25519Kyber768Draft00` |
| 客户端 | `tls-hybrid/client/client.go` | 连接服务端并导出密钥材料 |
| 端到端自测 | `tls-hybrid/e2e/test.go` | 一个进程内同时起服务端与客户端，并打印实际协商到的 KEX |

```sh
cd tls-hybrid/server
GOOS=linux   GOARCH=amd64 go build -o ../../dist/tls/server/linux_server        server.go
GOOS=windows GOARCH=amd64 go build -o ../../dist/tls/server/windows_server.exe  server.go

cd ../client
GOOS=linux   GOARCH=amd64 go build -o ../../dist/tls/client/linux_client        client.go
GOOS=windows GOARCH=amd64 go build -o ../../dist/tls/client/windows_client.exe  client.go
```

- 证书/私钥：`tls-hybrid/server/server_root_cert1.pem`、`server_root_key1.pem`
- 另有多份历史参考实现：`tls-hybrid/server/example.go`（`main1()`，不参与编译入口）、
  `tls-hybrid/client/legacy/`、`tls-hybrid/e2e/example.go`

### 逐组测试（`-kex`）

客户端与服务端都支持 `-kex`，只启用指定的一组，便于按验收大纲逐组验证：

| `-kex` 取值 | 量子安全等级 |
|---|---|
| `SM2Kyber512Draft00` | 128 比特 |
| `X25519Kyber512Draft00` | 128 比特 |
| `X25519Kyber768Draft00` | 192 比特 |
| `SM2Kyber768Draft00` | 192 比特 |
| **`X25519Kyber1024Draft00`** | **256 比特** |
| **`SM2Kyber1024Draft00`** | **256 比特** |
| `X25519HQC-128`（别名 `X25519HQC1`） | 128 比特（需 `-tags pq_hqc` 构建） |
| `X25519HQC-256`（别名 `X25519HQC5`） | 256 比特（需 `-tags pq_hqc` 构建） |
| `X25519` | 传统算法（兼容性回退） |

端到端自测示例（已实测通过）：

以下命令**在项目根目录执行**（路径均为项目内相对路径）：

```sh
( cd tls-hybrid/e2e && go build -o ../../.build/e2e . )
.build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem \
           -ca .build/certs/server_root_cert1.pem -kex X25519Kyber1024Draft00 -addr localhost:8099
# 输出：🔑 使用密钥交换算法: X25519Kyber1024Draft00 (混合后量子, 256 比特量子安全等级)
```

> 证书准备（`.build/certs/`）见 [`docs/测试大纲-输入及操作-细化.md`](测试大纲-输入及操作-细化.md) §0.3。

### 示例程序的参数

| 参数 | 适用 | 说明 |
|---|---|---|
| `-kex A,B,C` | e2e / server / client | 启用的密钥交换组，逗号分隔（顺序即偏好，默认全部）。支持 `DummyKex` 用于触发 HelloRetryRequest |
| `-verify` | e2e / client | 客户端启用标准证书链校验（默认关闭以便自测） |
| `-ca <文件>` | e2e / client | 信任的 CA 文件（client 默认为工作目录下的 `server.crt`） |
| `-cert <文件>` `-key <文件>` | e2e / server | 服务端证书与私钥（server 默认 `./server_root_cert1.pem`、`./server_root_key1.pem`，即历史行为；指定后可从项目根目录用相对路径启动） |
| `-msg` / `-msg-hex` | e2e | 客户端发送的文本 / 十六进制二进制数据 |
| `-addr` / `-showkex` | e2e | 监听地址 / 是否打印协商结果 |

环境变量：设置 `SSLKEYLOGFILE=<文件>` 可让上述程序把 TLS 会话密钥写入该文件，供 Wireshark 解密
（Wireshark → 首选项 → Protocols → TLS → (Pre)-Master-Secret log filename）。仅供测试使用。

性能测试工具（`tools/tlsbench`，需用打补丁的 GOROOT 编译）：

```sh
cd tools/tlsbench && go build -o ../../.build/tlsbench .
../../.build/tlsbench -mode server -addr :8099 -cert <证书> -key <私钥> -kex X25519Kyber1024Draft00 &
../../.build/tlsbench -mode client -addr localhost:8099 -kex X25519Kyber1024Draft00 -n 200
../../.build/tlsbench -mode client -addr localhost:8099 -kex X25519Kyber1024Draft00 -c 50 -n 1000
```

---

## C. 构建抗量子证书生成工具（pqcert）

不需要补丁工具链，Go 1.25+ 即可：

```sh
cd pqcert/pure-pq        && go build .        # 纯抗量子链：Kyber / Dilithium / SPHINCS / 256 比特等级链
cd pqcert/sm2            && go build .        # SM2 与抗量子混合链（含 256 比特链）
cd pqcert/x509-multi     && go build .        # 多算法 X.509 链（含 ML-DSA-87 / Kyber-1024 用户证书）
cd pqcert/gen-pq-chain   && go run .          # 读 ../data/public_keys.txt，输出到 ../certs-sample
cd pqcert/gen-sm2-chain  && go run .          # 同上（SM2 版）
```

**量子安全等级覆盖（三个工具一致）**

| 等级 | 签名（格） | 签名（哈希） | KEM |
|---|---|---|---|
| 128 比特 | ML-DSA-44 / Dilithium2 | SLH-DSA-SHA2-128s / 128f | Kyber-512 |
| 192 比特 | ML-DSA-65 / Dilithium3 | SLH-DSA-SHA2-192s / 192f | Kyber-768 |
| **256 比特** | **ML-DSA-87 / Dilithium5** | **SLH-DSA-SHA2-256s / 256f** | **Kyber-1024** |

SLH-DSA 由 CIRCL v1.6.3 提供，`schemes.ByName("SLH-DSA-SHA2-256f")` 即可切换；
实测耗时（本机）：128s 签名 0.85s、128f 0.04s、192s 1.50s、192f 0.07s、
256s 1.31s、256f 0.14s；`pure-pq` 五条链全部生成+验签总耗时约 7s。
`s`（小签名/慢）与 `f`（大签名/快）按需选择，本仓库链验证用 `s` 变体、批量出证书用 `f` 变体。

> 三个工具现在都覆盖 SLH-DSA：`pure-pq`（纯抗量子链，含「256 比特等级哈希签名链」）、
> `x509-multi`（192f/256f 用户证书）、`sm2`（256 比特 SM2 + SLH-DSA 双重签名链）。
> `gen-pq-chain` / `gen-sm2-chain` 只做外部 SM2/ML-DSA 公钥导入签发，不涉及 SLH-DSA。

- 外部公钥数据：`pqcert/data/public_keys.txt`（含 `[SM2]`、`[ML-DSA-44]`、`[ML-DSA-44-Signature]`、`[PQ-ECC-Signature]` 段）
- 示例输出：`pqcert/certs-sample/`（`mldsa_root.pem`、`mldsa_user.pem`、`sm2_root.pem`、`sm2_user.pem`）
- 各工具自身目录下的 `certs*`、`pq_x509_certs/`、`pure_pq_certs/` 是运行时生成的样例输出；
  256 比特等级的产物文件名带 `mldsa87` / `kyber1024` 标识

> OID 说明：ML-DSA OID 沿用项目既有编法（`2.16.840.1.101.3.4.11/12/13`）。
> 若要严格对齐最终标准草案，ML-DSA-44/65/87 应为 `2.16.840.1.101.3.4.3.17/18/19`，
> 但改动会影响已有证书，需评估后再统一。

---

## D. 已知问题

1. **`pqtls-1.3/{client,server}` 的入口编译不过**

   ```
   client.go:82: unknown field ProtocolType in struct literal of type tls.Config
   client.go:82: undefined: tls.QuantumSupportAKEX
   ```

   `tls.ProtocolType` / `tls.QuantumSupportAKEX` 在系统 Go、仓库里的补丁 Go 1.22.12、
   以及 go1.25.1 / go1.25.12 / go1.26.5 中都不存在；同时 `internal/crypto/mytls`（含
   `handshake_client.go`、`handshake_server_tls13.go`）虽然实现了 Kyber768 混合密钥交换，
   但唯一引用它的 `pqtls-1.3/server/client.go:runClient()` **没有任何地方调用**。

   即：这份 `internal/crypto/mytls` 目前是"挂空挡"的 fork，需要先接进入口再谈换算法。

2. **`pqtls-1.3` 与 `tls-hybrid` 是两条独立的线**：前者（`internal/crypto/mytls` + `tls.ProtocolType`）
   不在验收路径上；验收大纲的测试环境写的是 go1.22.12，对应的是 `tls-hybrid` + 补丁 GOROOT。

---

## E. TLS 侧 HQC（混合组 X25519HQC-128 / X25519HQC-256）

HQC 已实现：CIRCL 不含 HQC，因此用 cgo 调 **liboqs**，并复用 CIRCL 的混合构造。
为不破坏跨平台交叉编译，HQC 做成**可选编译**：

| 构建方式 | HQC 是否可用 | cgo |
|---|---|---|
| `go build .`（默认） | ❌（`tls.HQCEnabled() == false`，请求 HQC 会明确报错） | 不需要，可 `CGO_ENABLED=0` 交叉编译 |
| `go build -tags pq_hqc .` | ✅ | 需要 liboqs |

完整设计与实测见 **[`HQC-TLS-最小改造路线.md`](HQC-TLS-最小改造路线.md)**。速查：

```sh
# 1) 编译 Linux 版 liboqs（只保留 HQC）
cmake -S <liboqs 源码> -B <build 目录> -DCMAKE_INSTALL_PREFIX=<前缀> \
      -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=OFF -DOQS_ENABLE_KEM_HQC=ON \
      -DOQS_ENABLE_KEM_KYBER=OFF -DOQS_ENABLE_KEM_ML_KEM=OFF \
      -DOQS_ENABLE_KEM_BIKE=OFF -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
      -DOQS_ENABLE_KEM_FRODOKEM=OFF -DOQS_ENABLE_KEM_NTRUPRIME=OFF \
      -DOQS_ENABLE_SIG_DILITHIUM=OFF -DOQS_ENABLE_SIG_FALCON=OFF -DOQS_ENABLE_SIG_SPHINCS=OFF
cmake --build <build 目录> -j$(nproc) && cmake --install <build 目录>

# 2) 带 HQC 构建 tls-hybrid
export CGO_ENABLED=1
export CGO_CFLAGS="-I<前缀>/include"
export CGO_LDFLAGS="-L<前缀>/lib -loqs"
go build -tags pq_hqc -o e2e_hqc ./tls-hybrid/e2e

# 3) 逐组测试
./e2e_hqc -cert ... -key ... -ca ... -kex X25519HQC-128 -addr localhost:8095
./e2e_hqc -cert ... -key ... -ca ... -kex X25519HQC-256 -addr localhost:8095
```

**HQC 尺寸与口径**（liboqs）：

| 项 | 值 |
|---|---|
| 算法名 | `"HQC-128"` / `"HQC-192"` / `"HQC-256"`（`src/kem/kem.h`） |
| HQC-128 | public key 2249 B，ciphertext 4433 B，shared secret 64 B |
| HQC-256 | public key 类似量级，ciphertext 更大；共享密钥 64 B |
| 量子安全等级 | HQC-128 → 128 比特；HQC-256 → 256 比特（HQC-192 属 Cat 3，不建议标 256） |
| 对照 Kyber768 | public key 1184 B，ciphertext 1088 B，shared secret 32 B |

> 备注：`pqcert/*/go.mod` 里的 `github.com/open-quantum-safe/liboqs-go` 与
> **TLS 侧的 HQC 实现无关**——HQC 适配器直接走 cgo 调 liboqs 的 C API
> （`OQS_KEM_*`），不依赖 liboqs-go，因此不需要 `liboqs-go.pc`。
