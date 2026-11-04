# TLS 网关 kex 算法配置

配置文件中的 `kex` 填写密钥交换组名，例如：

```json
"kex": ["SM2MLKEM512"]
```

`bin/pqc-gateway` 支持以下 8 个组；`bin/pqc-gateway-hqc` 也支持它们：

- `SM2MLKEM512`（44 档默认）
- `SM2MLKEM1024`（87 档默认）
- `SM2Kyber512Draft00`
- `SM2Kyber768Draft00`
- `SM2Kyber1024Draft00`
- `X25519Kyber512Draft00`
- `X25519Kyber768Draft00`
- `X25519Kyber1024Draft00`

`bin/pqc-gateway-hqc` 另外支持 4 个组：

- `X25519HQC-128`
- `X25519HQC-256`
- `SM2HQC-128`
- `SM2HQC-256`

网关和客户端应配置相同的组名。客户端 `probe` 用 `-kex SM2MLKEM512` 指定；如需配置多个组，JSON 数组中逐个填写，`probe` 则用逗号分隔。HQC 组在两端都要使用 `pqc-gateway-hqc`。旧 Kyber 组用于兼容旧客户端。以上 12 个组已在本地完成 TLS 1.3 握手测试。
