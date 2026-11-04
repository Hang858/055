# TLS 源码部署测试包

面向 Ubuntu 20.04 / x86_64 的服务端部署包：把 TLS 源码、补丁版 Go 工具链、预编译二进制、测试脚本与固定端点装到服务端，部署完成后**只在本机作为客户端执行测试**，测试期间不再登录服务端。

## 包内容

```
src/tls-hybrid/         TLS 源码（server、client、e2e、tools/tlsbench）
src/tools/              tshark_check.sh（握手解析）、tls_abnormal_hello.py、pcap_capture.py、tls_middlebox.py
src/tls-test-scripts/   24 条用例脚本 + lib.sh、config.env、run_all.sh、
                        server-endpoints.sh（服务端端点）、run-server-side.sh（服务端侧用例）
bin/                    server、client、e2e、tlsbench 及 HQC 版本（预编译）
bin/certs/              测试证书与私钥
bin/go-min.tgz          补丁版 Go 1.22.12 工具链（裁剪版，约 70 MB）
bin/go-kemtls-min.tgz   补丁版 Go 1.25.1 PQTLS 工具链（TLS-1-13 用，约 79 MB）
src/kemtls/             cloudflare_server/client 源码与 pqcerts 证书（TLS-1-13）
patches/                go_kemtls 补丁说明（ServerKeyGen transcript/长度校验）
deploy.sh               服务端部署脚本（安装 + 启动固定端点）
                       另构建 ServerKeyGen 1.5-RTT 变体（cloudflare_*_keygen）
run-tests.sh            客户端侧入口（检查端点后执行 22 条用例）
SHA256SUMS              完整性校验
```

## 服务端部署

```sh
tar -xzf pqc-tls-source-<日期>.tar.gz
cd pqc-tls-source-<日期>
sudo ./deploy.sh /opt/pqc-tls-test                   # 使用预编译二进制 + 启动端点
sudo ./deploy.sh /opt/pqc-tls-test --rebuild         # 用包内 Go 从源码重编非 HQC 二进制
sudo ./deploy.sh /opt/pqc-tls-test --no-endpoints    # 只安装，不启动端点
```

`deploy.sh` 依次执行：校验 SHA256 → 复制源码与脚本 → 安装二进制与证书 → 解压补丁版 Go → 安装 go_kemtls 并编译 cloudflare server/client（含 KEM 变体和 ServerKeyGen 1.5-RTT 变体）→ 在目标机重编 8 个二进制（非 HQC 静态，HQC 用私有 liboqs）→ 启动固定端点。

ServerKeyGen 变体用于验证论文第 3.3 节的 1.5-RTT 流程，可单独运行：

```sh
cd /opt/pqc-tls-test
bash tls-test-scripts/serverkeygen-smoke.sh
```

固定端点（服务端 `endpoints/<端口>.{log,pid}`）：

| 端口 | 用途 |
|---|---|
| 8080 | 全部非 HQC 组 |
| 8181 | 全部 HQC 组（8081 在测试环境被其他服务占用） |
| 8082 | 协商策略（X25519,X25519Kyber1024Draft00） |
| 8099 | tlsbench 压测服务端 |
| 8111 | 过期证书端点（TLS-1-10） |

端点管理：

```sh
bash /opt/pqc-tls-test/tls-test-scripts/server-endpoints.sh {start|stop|status}
```

## 客户端执行测试

客户端机器需要：`.build/{client,client_hqc,e2e,tlsbench}`、`.build/certs`、`tools/`、`tls-test-scripts/`（可直接用仓库；或从包内取 `src/tls-test-scripts`、`src/tools`、`bin/client*`、`bin/certs` 按相同目录摆放），并安装 `python3`、`tcpdump`、`tshark`、`openssl`（握手解析依赖 tshark）。

```sh
# 在本机仓库根目录
sudo bash tls-test-scripts/run_all.sh     # 24 条：22 条客户端 + SSH 执行服务端侧 2 条
RUN_SERVER_SIDE=0 sudo bash tls-test-scripts/run_all.sh   # 只跑客户端 22 条
bash tls-test-scripts/run_all.sh          # 无 root 时抓包/解析记 SKIP，其余照跑
```

`run_all.sh` 通过免密 SSH（`SERVER_SSH`，默认 `xgs-server`）在服务端 `SERVER_DIR` 下执行 TLS-2-5、TLS-1-13，并把结果取回到 `$RUN_DIR/server-side/` 合并进同一份 `summary.tsv`。SSH 不可用时这两条保留为 `SERVER-SIDE`，不影响其余用例。

结果：`tls-test-scripts/results/run-<时间戳>-<pid>/<用例标识>/`，含 `commands.log`、`output.log`、`summary.txt`、`captures/`、`analysis/`；汇总见同目录 `summary.tsv`。

服务端地址与端口在 `tls-test-scripts/config.env` 配置（默认 `SERVER_HOST=192.168.2.165`，可用环境变量覆盖）。

## 服务端侧用例

TLS-2-5（服务端资源消耗）与 TLS-1-13（异构认证，读服务端日志并移走抗量子私钥）必须在服务端本机执行：

```sh
cd /opt/pqc-tls-test
bash tls-test-scripts/run-server-side.sh
```

`run_all.sh` 会把这两条标为 `SERVER-SIDE` 并跳过，不计入失败。

## 覆盖与限制

- 24 条用例由 `run_all.sh` 一次执行：客户端 22 条 + 服务端侧 2 条（TLS-2-5、TLS-1-13）。
- TLS-1-13 的四模式矩阵由部署阶段预编译的 KEM 变体（`cloudflare_server_kem`/`cloudflare_client_kem`）在运行阶段依次执行。
- TLS-2-7 的 netem 时延注入需要 root；中间盒三策略由 `tools/tls_middlebox.py` 实现，无需 root。
- 握手解析依赖 `tshark`；未安装时解析步骤记 SKIP，其余握手/性能断言照常执行。
- TLS-3-4（本机编译并回环运行）、TLS-3-5（Windows 交叉编译）按定义在本机完成。
- 性能/时延规模可在 `tls-test-scripts/config.env` 调整（`PERF_N`、`CONCURRENCY_N`、`NETEM_N` 等）。
