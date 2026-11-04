# 服务端运行程序与启动脚本

本目录保存"服务端跑什么程序"的两种形态与启动方式，测试脚本据此选择。

## 1. 测试脚本默认使用的服务端（编译产物）

`tls-test-scripts/TLS-*.sh` 默认使用项目内编译好的 `.build/server`（由 `tls-hybrid/server` 编译而来），客户端为 `.build/client`，性能用例为 `.build/tlsbench`，端到端用例为 `.build/e2e`。它们都是编译后的 ELF 可执行文件，不是 `go run`。服务端源码在 `tls-hybrid/server/`，重新编译：

```sh
cd tls-hybrid/server && ../../.build/go/bin/go build -o ../../.build/server .
```

## 2. 交付运行包的服务端（pqc-gateway，Ubuntu 20.04）

交付运行包为 `dist/pqc-gateway-hybrid-mlkem-ubuntu20.04-amd64-20261013.zip`（2026-10-21，最新），解压后 `bin/` 下是 `pqc-gateway`、`pqc-gateway-hqc`、`pqc-certtool` 三个可执行文件，另有 `config/`、`demo/44`、`demo/87`、`docs/`、`install.sh`、`systemd/`，**不含源码**。若服务端跑这个交付包，用 `run-gateway.sh` 启动。它按 JSON 配置（`listen`、`upstream`、`cert`、`key`、`kex`、`client_ca`）工作，客户端用同一程序的 `probe` 子命令：

```sh
bash tls-test-scripts/server-runtime/run-gateway.sh            # 使用默认配置
GATEWAY_BIN=/opt/pqc-gateway-hybrid/bin/pqc-gateway \
LISTEN=127.0.0.1:9443 UPSTREAM=http://127.0.0.1:9081 \
KEX='"SM2Kyber512Draft00"' bash tls-test-scripts/server-runtime/run-gateway.sh
```

已在本机用交付包自带 `demo/44` 验证（`smoke-gateway.sh`）：`probe` 输出 `negotiated_kex=SM2MLKEM512`、`authenticated_signature=sm2-mldsa-44 codepoint=0xfea0`、`certificate_verified=true`、HTTP 200，网关日志 `client_cert_verified=true`。

注意：`pqc-gateway` 的 `-kex` 写在配置文件里，客户端用 `probe -kex`，与 `.build/server -kex` 的用法不同；`DummyKex` 触发 HRR、`e2e`、`tlsbench` 等用例需要改写命令后才能对这套程序执行。

## 3. 异构 Sig/KEM 认证服务端（TLS-1-13）

TLS-1-13 使用 `go_kemtls` + `cloudflare_server`。`kemtls/` 下保留了修复后的 `server.go`、`client.go` 源码，验签缺陷的补丁见 `patches/go_kemtls-fix-pq-sign-verify.patch`。启动：

```sh
bash tls-test-scripts/server-runtime/run-kemtls-server.sh
```

修复内容：验签失败返回非 nil 错误；服务端签名失败中止握手；客户端验签失败不再静默放行。

## 4. 远端

`config.env` 中 `MODE=remote` 时，服务端应在目标机 `/opt/pqc-gateway-hybrid` 下用上述 `run-gateway.sh` 启动；当前脚本的远端分支尚未联调。
