# 抗量子密码协议库与证书生成工具

《银行业及其关键基础设施信息系统的抗量子密码迁移技术研究》课题三
「银行业典型信息系统抗量子密码安全协议迁移技术」的源码与文档仓库。

包含三部分成果：**国产商用密码与抗量子密码混合的 TLS 协议源码库**、
**TLS 1.3 抗量子客户端/服务端实验代码**、**抗量子证书生成工具**，
以及配套的验收测试大纲与研究文档。

---

## 目录结构

```
.
├── tls-hybrid/        混合（国密 SM2 + Kyber）TLS 协议源码库及示例程序
│   ├── server/        服务端示例（server.go）+ 历史参考实现（example.go）
│   ├── client/        客户端示例（client.go）+ legacy/ 历史版本
│   ├── e2e/           单进程端到端自测（test.go），打印实际协商的 KEX
│   └── README.md      原始构建命令
├── pqtls-1.3/         TLS 1.3 抗量子客户端/服务端（含 internal/crypto/mytls 标准库 fork）
│   ├── server/
│   └── client/
├── pqcert/            抗量子证书生成工具
│   ├── pure-pq/       纯抗量子证书链（Kyber / Dilithium / SPHINCS）
│   ├── sm2/           SM2 与抗量子算法混合证书链
│   ├── x509-multi/    X.509 多算法证书链
│   ├── gen-pq-chain/  外部 ML-DSA 公钥导入签发
│   ├── gen-sm2-chain/ 外部 SM2 公钥导入签发
│   ├── data/          外部公钥数据（public_keys.txt）
│   ├── certs-sample/  示例输出证书
│   └── certs-delivery/ 交付证书
├── docs/              测试大纲、模板、研究文档与图示
│   ├── TLS协议测试大纲.docx
│   ├── 抗量子证书测试大纲.docx
│   ├── 模板-测试大纲.docx
│   ├── 博士+刘凯博+TLS协议抗量子密码迁移技术研究.pdf
│   ├── preview_2023YFC3305503.pdf
│   ├── 测试功能概述.md
│   ├── BUILD.md       构建说明（含补丁工具链、liboqs、`-kex` 逐组测试）
│   ├── HQC-TLS-最小改造路线.md   TLS 侧接入 HQC 的最小改动方案
│   └── assets/        TLS 握手流程 / 密钥材料 / 测试拓扑图
├── patches/           Go 1.22.12 crypto/tls 抗量子补丁（可复现）
└── dist/              交付二进制留档（linux_*/windows_*.exe，不进 git）
```

---

## 成果状态

| 组件 | 抗量子能力 | 构建状态 |
|---|---|---|
| `tls-hybrid/` | 混合密钥交换按量子安全等级覆盖 **128 / 192 / 256 比特**：`SM2Kyber512Draft00`、`X25519Kyber512Draft00`（128）；`X25519Kyber768Draft00`、`SM2Kyber768Draft00`、`X25519Kyber768Draft00Old`、`P256Kyber768Draft00`（192）；**`X25519Kyber1024Draft00`、`SM2Kyber1024Draft00`（256）**；保留 `X25519` 回退 | 需 `patches/` 里打补丁的 Go 1.22.12 ✅（已实测 6 组握手） |
| `pqcert/` | 签名（格）**ML-DSA-44/Dilithium2（128）、ML-DSA-65/Dilithium3（192）、ML-DSA-87/Dilithium5（256）**；签名（哈希）**SLH-DSA-SHA2-128s/128f、192s/192f、256s/256f**；KEM **Kyber-512、Kyber-768、Kyber-1024** | 用 Go 1.25+ 可直接编译运行 ✅（三个工具均实跑通过） |
| `pqtls-1.3/` | `internal/crypto/mytls` fork 内实现 X25519+Kyber768 混合 | ⚠️ 入口引用了未定义符号，编译不过，见下 |
| HQC | **未实现**（只有两行注释 `//NextProtos: []string{"pq-HQC-128"}`） | ❌ 改造路线见 [`docs/HQC-TLS-最小改造路线.md`](docs/HQC-TLS-最小改造路线.md) |

---

## 快速开始

完整步骤见 [`docs/BUILD.md`](docs/BUILD.md)：

1. 用 `patches/` 重建打补丁的 Go 1.22.12（当前仓库里的 `go1.22.12/` 是 macOS 版，Linux 需重建）
2. 用该 GOROOT 编译 `tls-hybrid/`，产物放 `dist/`
3. 用 Go 1.25+ 编译/运行 `pqcert/` 下的证书工具

已实测通过的项：

```sh
# TLS：Linux 版补丁工具链重建 + 逐组握手（含 256 比特组）
cd tls-hybrid/e2e && go build -o /tmp/e2e .
/tmp/e2e -cert server_root_cert.pem -key server_root_key.pem \
         -ca server_root_cert1.pem -kex X25519Kyber1024Draft00 -addr localhost:8099

# 证书工具全部可编译可运行
cd pqcert/pure-pq && go build .         # 五条链（含 ML-DSA-87、SLH-DSA-256s）验签全部通过
cd pqcert/sm2 && go build .             # 含 256 比特链（ML-DSA-87 + Kyber-1024）
cd pqcert/x509-multi && go build .      # 含 ML-DSA-87 / Kyber-1024 / SLH-DSA-192f/256f 用户证书
cd pqcert/gen-pq-chain && go run .      # 输出至 pqcert/certs-sample/
cd pqcert/gen-sm2-chain && go run .     # 输出至 pqcert/certs-sample/
```

---

## 已知问题

1. **`pqtls-1.3` 入口编译失败**：`client.go:82` / `server.go:139` 使用了
   `tls.ProtocolType` 与 `tls.QuantumSupportAKEX`，这两个符号在任何可用 Go 中都不存在；
   而真正实现 Kyber 混合的 `internal/crypto/mytls` 未被任何入口调用
   （`pqtls-1.3/server/client.go` 的 `runClient()` 无调用点）。
2. **HQC 未接入**：CIRCL 不提供 HQC，只能引入 liboqs。最小改造路线（适配器要实现的
   13 个 `kem.Scheme` 方法、build tag 方案、平台构建与风险）见
   [`docs/HQC-TLS-最小改造路线.md`](docs/HQC-TLS-最小改造路线.md)。
3. **`internal/crypto/mytls` 有 5 份副本**：`pqtls-1.3/{server,client}` 与
   `pqcert/{pure-pq,sm2,x509-multi}` 各一份（后三者已删除 `internal/`，因证书工具并不依赖它）。
   当前 `pqtls-1.3` 两份内容 165/167 文件相同，暂未合并去重。
4. **工具链平台问题**：`go1.22.12/bin/go` 是 Mach-O（macOS）可执行文件，Linux 上不可执行。

---

## 版本库说明

- 提交历史：`baseline`（整理前完整快照，便于回溯）→ `整理`（重命名/归档/清理）
  → `工程化文件`（README/.gitignore/补丁）→ `安全等级修正`（Kyber-1024 + ML-DSA-87）
  → `SLH-DSA 等级补全`（192s/192f/256s/256f）。
- 以下内容**不入库**（见 `.gitignore`）：
  - `go1.22.12/`（266M macOS 工具链，用 `patches/` 重建）
  - `dist/`（交付二进制，可重新编译）
  - 构建产物、`.DS_Store`、`.idea/` 等
- 需要某次整理中被删除的文件时：`git checkout b4acd4d -- <路径>`。
