# TLS 补丁说明

## serverkeygen-transcript-length.patch

对应论文第 3.3 节的 1.5-RTT 流程优化（`QuantumSupportServerKeyGen`）。

修改两处：

1. 客户端发送 `pqClientKeyExchange` 时使用 `hs.transcript`，把该消息纳入 TLS 1.3 握手摘要；
2. 服务端读取时使用 `hs.transcript`，并在切片前校验内层类型/长度，避免畸形报文触发 panic。

应用方式：解压 `go-kemtls-min.tgz` 后，在 Go 源码根目录执行：

```bash
patch -p1 < serverkeygen-transcript-length.patch
```

然后重新编译客户端/服务端。
