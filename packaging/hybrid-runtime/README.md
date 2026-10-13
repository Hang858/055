# TLS 安全网关运行包

适用系统：Ubuntu 20.04 / x86_64。解压后运行`./install.sh /opt/pqc-gateway-hybrid`。安装和配置步骤见`docs/安装配置说明.md`，验收步骤见`docs/本机和目标机验收.md`。

`bin/pqc-gateway`提供网关服务与客户端 probe，默认支持 SM2+ML-KEM-512/1024；`bin/pqc-gateway-hqc`额外支持 HQC 密钥交换；`bin/pqc-certtool`生成 SM2+ML-DSA-44/87 证书。三个程序均为 Linux x86_64 静态可执行文件。压缩包不含网关、证书工具或 Go/TLS 源码。SM2+ML-KEM 是本项目私有 TLS 组，不能直接与通用浏览器互通。

`demo/`里的证书和私钥只供联调。正式部署须用证书工具重新生成厂内专用证书。
