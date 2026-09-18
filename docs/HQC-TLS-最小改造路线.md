# TLS 侧 HQC 混合密钥交换：最小改造路线与实现说明

> 状态：**已实现并实测通过**。
> 新增混合组 `X25519HQC-128`（128 比特）、`X25519HQC-256`（256 比特），
> 对应 `docs/TLS协议测试大纲.docx` 第 111 行的 `X25519HQC1/5`。

## 1. 结论：为什么只能走 liboqs

| 事实 | 证据 |
|---|---|
| CIRCL 没有 HQC | `go1.22.12/src/vendor/github.com/cloudflare/circl/kem/` 下只有 `hybrid`、`kyber`、`mlkem` |
| 仓库里没有其它 HQC 实现 | 原先只有两行注释 `//NextProtos: []string{"pq-HQC-128"}` |
| 可用的 HQC 实现 | liboqs（`OQS_ENABLE_KEM_hqc_128/192/256 = 1`，算法名 `"HQC-128"`，见 `src/kem/kem.h`） |

TLS 侧的 KEM 全部经由一个接口取得（`go1.22.12/src/crypto/tls/cfkem.go`）：

```go
func curveIdToCirclScheme(id CurveID) kem.Scheme
```

所以最小改动的本质是：**写一个用 liboqs 实现的 `kem.Scheme`，再在 `cfkem.go` 里注册两个 CurveID。**

## 2. 实现（改动清单）

| 文件 | 改动 |
|---|---|
| `crypto/tls/hqckem.go`（新增，`//go:build pq_hqc`） | 用 cgo 调 liboqs，实现 CIRCL `kem.Scheme` 的全部 13 个方法 |
| `crypto/tls/hqckem_stub.go`（新增，`//go:build !pq_hqc`） | 占位实现：`newHQCScheme` 返回 nil、`hqcEnabled = false`，保证默认构建零 cgo 依赖 |
| `crypto/tls/cfkem.go` | 新增 `X25519HQC128 = CurveID(0xfe38)`、`X25519HQC256 = CurveID(0xfe39)`；`curveIdToCirclScheme` 加两个 case；导出 `HQCEnabled()` |
| `vendor/.../circl/kem/hybrid/hybrid.go` | 新增 `X25519KEM()` 与 `NewHybridScheme(name, first, second)` —— 复用 CIRCL 既有的混合构造 |
| `tls-hybrid/{server,client,e2e}` | `supportedKEX` 在 `tls.HQCEnabled()` 时追加两个 HQC 组；`-kex` 支持 `X25519HQC-128/256`（以及 `X25519HQC1/5` 别名） |

**混合构造与 Kyber 组完全一致**（复用 CIRCL 的 `scheme` 类型）：

```
key_share 载荷 = X25519 公钥(32B) || HQC 公钥
ciphertext     = X25519 公钥(32B) || HQC 密文
shared_secret  = X25519_ss(32B) || HQC_ss(64B)      ← 直接拼接
```

尺寸（HQC-128）：公钥 2249B、密文 4433B、共享密钥 64B；混合后公钥 2281B、密文 4465B。

### 实现注意点

- liboqs 的通用 API **不提供「由种子确定性生成密钥对 / 确定性封装」**。
  因此适配器的 `DeriveKeyPair(seed)` 与 `EncapsulateDeterministically(pk, seed)` 忽略种子、
  退化为随机版本（`SeedSize()` / `EncapsulationSeedSize()` 声明为 32）。
  这不影响与本项目对端的互操作（客户端 Decapsulate 与服务端 Encapsulate 的结果一致），
  只影响测试向量的可复现性。
- cgo 不能直接调用 `OQS_KEM` 结构体里的函数指针，`hqckem.go` 用一组静态 C 辅助函数包了一层。

## 3. 构建

### 3.1 编译 Linux 版 liboqs（只保留 HQC，约 1 分钟）

```sh
cd <liboqs 源码目录>
cmake -S . -B build-linux -DCMAKE_INSTALL_PREFIX=<工作区>/.build/liboqs \
      -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=OFF \
      -DOQS_ENABLE_KEM_HQC=ON \
      -DOQS_ENABLE_KEM_BIKE=OFF -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
      -DOQS_ENABLE_KEM_FRODOKEM=OFF -DOQS_ENABLE_KEM_KYBER=OFF \
      -DOQS_ENABLE_KEM_ML_KEM=OFF -DOQS_ENABLE_KEM_NTRUPRIME=OFF \
      -DOQS_ENABLE_SIG_DILITHIUM=OFF -DOQS_ENABLE_SIG_FALCON=OFF \
      -DOQS_ENABLE_SIG_SPHINCS=OFF
cmake --build build-linux -j$(nproc) && cmake --install build-linux
# 校验：grep OQS_ENABLE_KEM_hqc build-linux/include/oqs/oqsconfig.h
```

### 3.2 用打补丁的 Go 1.22.12 构建（GOROOT 重建见 `BUILD.md` A 节）

```sh
export GOROOT=<打补丁的 GOROOT>
export CGO_ENABLED=1
export CGO_CFLAGS="-I<工作区>/.build/liboqs/include"
export CGO_LDFLAGS="-L<工作区>/.build/liboqs/lib -loqs"

# HQC 版本
go build -tags pq_hqc -o dist/tls/e2e/linux_e2e ./tls-hybrid/e2e
# 默认版本（不含 HQC，可 CGO_ENABLED=0 交叉编译出 Windows 产物）
GOOS=windows GOARCH=amd64 go build -o dist/tls/e2e/windows_e2e.exe ./tls-hybrid/e2e
```

## 4. 实测结果

```sh
$ e2e -kex X25519HQC-128 ...
🔑 使用密钥交换算法: X25519HQC-128 (混合后量子, 128 比特量子安全等级)

$ e2e -kex X25519HQC-256 ...
🔑 使用密钥交换算法: X25519HQC-256 (混合后量子, 256 比特量子安全等级)
🔒 服务器接收到: Secret quantum-safe message
📩 服务器响应: 量子安全响应: Secret quantum-safe message
⏱️ 总执行时间: 36.3ms
```

其它验证：

- 默认构建（不带 tag）请求 HQC 会被明确拒绝：
  `HQC 组需要带 -tags pq_hqc 构建并链接 liboqs；当前构建不含 HQC`
- `pq_hqc` 构建下原有各组（`X25519Kyber512Draft00`、`X25519Kyber1024Draft00`、
  `SM2Kyber512Draft00`、`X25519`）回归通过

## 5. 限制与注意事项

1. **HQC 版本需要 cgo**，因此 `CGO_ENABLED=0` 的交叉编译只在默认（无 HQC）构建下可用；
   Windows 的 HQC 产物需要在 Windows/mingw 环境构建（仓库里那份 Windows liboqs 正是这么来的）。
   默认构建完全不受影响，测试大纲的「跨平台编译运行」要求仍然满足。
2. **HQC-192 也可用**（把 `newHQCScheme("HQC-192")` 接上即可），但 NIST 口径下 HQC-192 属
   Category 3，"256 比特"建议用 HQC-256。SSH 测试大纲把 HQC192 记为 256 比特，两者口径不一致。
3. 码点 `0xfe38/0xfe39` 属项目自定义私有段（`X25519HQC` 无标准草案码点），
   与既有 `SM2Kyber512Draft00 = 0xfe34` 同一路数。
4. 安全等级对照：HQC-128 → 128 比特，HQC-256 → 256 比特。申报书「支持 2 类抗量子密码算法，
   可达到 128、256 比特的量子安全等级」中的「2 类」，正好由 **Kyber 与 HQC 两条技术路线**提供。
