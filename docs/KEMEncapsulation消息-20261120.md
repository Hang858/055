# 独立 KEMEncapsulation 消息（阶段 5b）

日期：2026-11-20
对应论文：FA-TLS 图 4/图 5、Appendix A 的 `KEMEncapsulation` 消息。

## 1. 消息定义

新增私有握手消息类型 `251`：

```
struct {
    uint8  type = 251;
    uint24 length;
    opaque ciphertext[length];
} KEMEncapsulation;
```

TLS 握手头本身带 uint24 长度，消息体只放密文本体。密文长度由 `length` 决定，
解析时要求 `len(data) == 4+length`，截断/超长直接拒绝。

## 2. 发送顺序

| 模式 | 客户端→服务端 | 服务端→客户端 |
|---|---|---|
| Sig-Sig | — | — |
| KEM-KEM | 服务器证书之后、客户端证书之前 | 客户端证书/CV 之后 |
| Sig-KEM（客户端 Sig、服务端 KEM） | 服务器证书之后、客户端证书之前 | — |
| KEM-Sig（客户端 KEM、服务端 Sig） | — | 客户端证书/CV 之后 |

- 客户端 `server_auth == KEM` 时，先发送 KEMEncapsulation，再发送自己的
  Certificate/CertificateVerify；
- 服务端 `server_auth == KEM` 时，在读取客户端 Certificate 之前先读取
  KEMEncapsulation 并解封装；
- 服务端 `client_auth == KEM` 时，读完客户端证书/CV 后发送
  KEMEncapsulation，客户端收到后解封装；
- 所有 KEMEncapsulation 都进入 transcript，参与 AHS 的 `TA`。

## 3. 清理

- `certificateMsgTLS13` 删除 `persistentCiphertextKEM` 字段，Certificate 消息
  只承载证书；
- 删除 `type 252`（`pqServerPersistentCiphertextMsg`）；
- 新增 `kemEncapsulationMsg` 及 `conn.go` 的消息分派；
- AHS 模式仍在 KEM 认证完成后安装 AHS，Finished 在 AHS 下发送。

## 4. 测试

| 场景 | 结果 |
|---|---|
| KEM-KEM | PASS，双方日志各有发送/接收 KEMEncapsulation |
| Sig-KEM | PASS，客户端发送、服务端接收 |
| KEM-Sig | PASS，服务端发送、客户端接收 |
| Sig-Sig | PASS（无 KEMEncapsulation） |
| 同构协商矩阵 | 12/12 PASS |
| 签名矩阵 | 10/10 PASS |
| PQ 链 + KEMEncapsulation | 握手成功 |
| 错误 KEM 私钥 | 失败（AHS 下 MAC/Finished 不匹配） |
| `TestKEMEncapsulationRoundTrip` | PASS |
| `TestKEMEncapsulationRejectsTruncated` | PASS |

## 5. 边界

- 新消息与阶段 4/5a 的旧 wire format 不兼容；对端必须同时升级；
- 仍是单个 `KEMEncapsulation` 消息承载一段密文，没有做多 KEM/多段扩展；
- KEM 模式下服务端仍发送 RSA `CertificateVerify`；
- 没有做 0-RTT、QUIC 端到端和证书链 PQ 组合矩阵。

## 6. 应用

补丁：`packaging/tls-source/patches/kem-encapsulation-message.patch`

顺序：

```bash
patch -p1 < slhdsa-tls-handshake.patch
patch -p1 < kem-registry-tls.patch
patch -p1 < protocol-mode-negotiation.patch
patch -p1 < kem-key-schedule.patch
patch -p1 < pq-certificate-chain.patch
patch -p1 < heterogeneous-auth.patch
patch -p1 < ahs-key-schedule.patch
patch -p1 < kem-encapsulation-message.patch
```
