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

---

## C. 构建抗量子证书生成工具（pqcert）

不需要补丁工具链，Go 1.25+ 即可：

```sh
cd pqcert/pure-pq        && go build .        # 纯抗量子链：Kyber / Dilithium / SPHINCS
cd pqcert/sm2            && go build .        # SM2 与抗量子混合链
cd pqcert/x509-multi     && go build .        # 多算法 X.509 链
cd pqcert/gen-pq-chain   && go run .          # 读 ../data/public_keys.txt，输出到 ../certs-sample
cd pqcert/gen-sm2-chain  && go run .          # 同上（SM2 版）
```

- 外部公钥数据：`pqcert/data/public_keys.txt`（含 `[SM2]`、`[ML-DSA-44]`、`[ML-DSA-44-Signature]`、`[PQ-ECC-Signature]` 段）
- 示例输出：`pqcert/certs-sample/`（`mldsa_root.pem`、`mldsa_user.pem`、`sm2_root.pem`、`sm2_user.pem`）
- 各工具自身目录下的 `certs*`、`pq_x509_certs/`、`pure_pq_certs/` 是运行时生成的样例输出

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

2. **HQC 尚未接入**：仓库里只有 `//NextProtos: []string{"pq-HQC-128"}` 两行注释，
   没有任何 HQC 实现；CIRCL 也不提供 HQC，所以只能走 liboqs。

---

## E. liboqs（接入 HQC 的前置条件）

现状：本机 `/home/hangzhang/liboqs-main/liboqs-main/build/` 是**用 mingw gcc
（`C:/Users/lu/.../gcc.exe`）编的 Windows 产物**，`/usr/local/lib` 下没有 `liboqs`，
Linux 上无法链接，需要重新编译。

```sh
cd /path/to/liboqs            # 例如 /home/hangzhang/liboqs-main/liboqs-main
rm -rf build && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DOQS_USE_OPENSSL=ON -DOQS_BUILD_ONLY_LIB=ON ..
ninja && sudo ninja install   # 或 cmake --build . && cmake --install .
```

liboqs-go 通过 `#cgo pkg-config: liboqs-go` 找库，需要提供 `liboqs-go.pc`：

```sh
# 模板在 liboqs-go 模块的 .config/ 下
cp ~/go/pkg/mod/github.com/open-quantum-safe/liboqs-go@*/".config"/liboqs-go.pc .
# 按实际安装位置修改 LIBOQS_INCLUDE_DIR / LIBOQS_LIB_DIR，然后
export PKG_CONFIG_PATH=$PWD:$PKG_CONFIG_PATH
```

HQC 相关事实（本机源码 `oqsconfig.h` 已确认开启）：

| 项 | 值 |
|---|---|
| 算法名（`Init()` 用） | `"HQC-128"` / `"HQC-192"` / `"HQC-256"`（`src/kem/kem.h:62`） |
| HQC-128 尺寸 | public key 2249 B，ciphertext 4433 B，shared secret 64 B |
| 对照 Kyber768 | public key 1184 B，ciphertext 1088 B，shared secret 32 B |

liboqs-go 用法（切换算法只改 `kemName` 字符串）：

```go
kemName := "HQC-128"
c := oqs.KeyEncapsulation{}
defer c.Clean()
c.Init(kemName, nil)
pk, _ := c.GenerateKeyPair()
ct, ss1, _ := s.EncapSecret(pk)
ss2, _ := c.DecapSecret(ct)
```

`pqcert/*/go.mod` 里已经预留了 `github.com/open-quantum-safe/liboqs-go`（当前是
`// indirect`，尚无代码引用）。
