# SM2＋ML-KEM 网关迁移计划

目标：把网关默认的两档密钥交换改为 FIPS 203 ML-KEM-512/1024 后端，保留已有 Kyber Draft 和 HQC 组，证书与 SM2＋ML-DSA 身份认证不变。

实现边界：只在补丁 Go `crypto/tls/cfkem.go` 新增两个项目私用组 `SM2MLKEM512` (`0xfe3c`) 与 `SM2MLKEM1024` (`0xfe3d`)；复用 CIRCL 现有 `hybrid.SM2KEM()` 与 `hybrid.NewHybridScheme()`。将 CIRCL v1.6.3 的原版 `kem/mlkem/mlkem512`、`mlkem1024` 加入 vendor 归档。更新网关组名映射、默认参数、配置样例和二进制包验收脚本。两组名称与码点均不宣称 IANA 标准化；标准化的是 ML-KEM 算法后端。

验收顺序：

1. 先把新组加入网关双向 TLS 测试并确认当前代码拒绝未配置的组名。
2. 加入两个 ML-KEM vendor 包及 TLS 组映射，验证 128/256 档双向握手、错误档位和旧 Kyber 互不协商。
3. 将网关样例和 probe 默认组改为新组；更新抓包长度表与交付包 smoke，使两档 ML-KEM、两档 HQC 及旧 Kyber 回归测试通过。
4. 生成可重放的 Go 补丁和 vendor 归档，重建 Linux amd64 静态程序与 ZIP；从最终 ZIP 解压执行完整验收。

本机为 Ubuntu 24.04；Ubuntu 20.04 厂内实机验收仍由目标环境完成。
