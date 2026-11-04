# TLS ServerKeyGen 1.5-RTT 修复与验证

日期：2026-11-04
对应论文：第 3.3 节“流程优化”，`QuantumSupportServerKeyGen` / `QuantumSupportSignCert_ServerKeyGen`

## 1. 改了什么

补丁文件：

`packaging/tls-source/patches/serverkeygen-transcript-length.patch`

修改 `go_kemtls` 的 `crypto/tls` 两处：

1. **客户端**：发送 `pqClientKeyExchange` 时传入 `hs.transcript`，把该消息纳入 TLS 1.3 握手摘要。
2. **服务端**：读取时传入 `hs.transcript`，并在切片前校验：
   - 外层长度必须等于 `4 + kyber768.CiphertextSize`；
   - 内层类型必须是 `typePQClientKeyExchange`；
   - 内层长度必须等于 `kyber768.CiphertextSize`。

服务端不再直接对未校验的报文做：

```go
pqKeyExchange.ciphertext[4 : kyber768.CiphertextSize+4]
```

避免畸形报文触发 panic。

## 2. 工具链更新

- 已修改 `.build/extracted/go_kemtls` 源码；
- 已重新打包 `.build/go-kemtls-min.tgz`，旧包备份为 `.build/go-kemtls-min.tgz.bak-20261104`；
- `packaging/tls-source/build-package.sh` 会打包新的工具链。

## 3. 本地验证

使用 `ProtocolType = QuantumSupportSignCert_ServerKeyGen`（13）重新编译 cloudflare server/client，本机回环 100 次：

```text
总次数: 100
平均耗时: 4.613333ms
最短耗时: 4.182928ms
最长耗时: 6.370153ms
TLS handshake OK, server verified
```

服务端日志：

```text
Server: ServerHello sent and flushed
等待抗量子密文信息
```

说明走的是 ServerKeyGen 分支：ServerHello 先带服务端 Kyber 公钥，客户端回 `pqClientKeyExchange` 密文，没有 HRR。

冒烟脚本：

```bash
bash tls-test-scripts/serverkeygen-smoke.sh
```

结果：

```text
PASS: 1.5-RTT ServerKeyGen 流程，100 次握手成功，未触发 HRR
```

## 4. 部署构建

`packaging/tls-source/deploy.sh` 已增加 ServerKeyGen 变体：

```text
cloudflare_server_keygen/server-keygen-linux
cloudflare_client_keygen/client-keygen-linux
```

由 `deploy.sh` 在解压 `go-kemtls-min.tgz` 后，把 `ProtocolType` 从 `QuantumSupportAKEX`（11）改为 `QuantumSupportSignCert_ServerKeyGen`（13）并编译。

## 5. 安全性判断

已修复的两点是实际安全问题：

- 客户端 PQ 贡献报文现在进入 transcript，和论文描述一致；
- 服务端对畸形长度不再直接切片，避免远程 panic/DoS。

仍需要补的验证：

1. 篡改 `pqClientKeyExchange` 密文，握手必须失败；
2. 截断/加长密文，服务端必须返回告警且不崩溃；
3. 重放旧密文，必须失败；
4. 强制降级到 11 或 ClassicAKE，不能被中间人利用；
5. 抓包确认没有 HelloRetryRequest；
6. 真实网络 RTT 下的 1.5-RTT 测量。

## 6. 性能定位

这条优化是：

- 比 HRR 路径的 2-RTT 少 0.5-RTT；
- 比标准 TLS 1.3 的 1-RTT 多 0.5-RTT；
- 适合 ClientHello 必须保持紧凑、不能携带 PQ 公钥的场景；
- 如果客户端能正常携带 key_share，标准 1-RTT 仍然更快。

## 7. 当前状态

- 代码：已修复并重新打包工具链；
- 功能：13 模式本地 100/100 通过；
- 测试：独立冒烟脚本已加入，尚未并入 24 条主用例；
- 交付：尚未重新生成 `dist/pqc-tls-source-*.tar.gz`，构建时会带上新工具链和补丁说明。
