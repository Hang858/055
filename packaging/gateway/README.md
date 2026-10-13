# TLS 安全网关交付包（Ubuntu 20.04 / x86_64）

用途：PQC 客户端 → TLS 1.3 网关 → 厂内 HTTP/HTTPS 业务服务。业务地址通过 JSON 配置，无需改源码。

先阅读 `docs/安装和配置说明.md`。完全离线可安装，无需 Go、Docker、liboqs 或联网下载依赖。

| 内容 | 路径 |
|---|---|
| 网关、验收客户端、现场证书生成、本机演示后端 | `bin/pqc-gateway` 的不同子命令 |
| 正式配置 / 本机演示配置 | `config/gateway.json` / `config/demo.json` |
| 可直接自测的证书和私钥（仅演示） | `certs-demo/` |
| 原项目五个证书工具及新生成样例 | `certificate-tools/` |
| systemd 服务文件 | `systemd/pqc-gateway.service` |
| 安装、证书配置、运维、验收、能力边界 | `docs/` |
| 源码和依赖、TLS 工具链源码及补丁 | `source/` |
| 构建/验收实测记录 | `validation/` |
| 文件完整性清单 | `SHA256SUMS` |

PQC 浏览器按要求未包含。`probe` 是命令行验收客户端，不是浏览器。

本版本基于项目既有 Kyber Draft00 混合密钥交换；网关运行证书使用 ECDSA-P256，不能将其表述为全链路 PQ 身份认证或最终 ML-KEM 标准兼容产品。原证书工具的纯 PQ / 多算法研究证书单独交付，未经兼容验证不能替换网关运行证书。详见 `docs/能力与证书对应说明.md`。
