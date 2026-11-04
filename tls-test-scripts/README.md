# TLS 测试脚本目录（客户端视角）

按《国产商用密码与抗量子密码混合的协议源码库测试大纲》附录 B 的 TLS 用例，一条用例一个脚本，脚本名即"用例标识 + 用例名称"。

测试拓扑：**服务端机器只运行服务端程序并预启动固定端点，本机作为客户端执行全部脚本**。脚本不登录服务端，只发起网络连接；每条用例保存输入的每条指令、命令输出、本机抓到的报文、解析结果与步骤级结论。

## 目录结构

```
tls-test-scripts/
├── lib.sh                 公共函数（日志、远端端点探测、抓包、断言、结果目录）
├── config.env             运行配置（服务端地址、端点端口、规模、网卡）
├── run_all.sh             执行 22 条客户端用例，并 SSH 到服务端跑 TLS-2-5、TLS-1-13，合并汇总
├── server-endpoints.sh    服务端侧：预启动 8080/8181/8082/8099/8111 端点
├── run-server-side.sh     服务端侧：执行 TLS-2-5、TLS-1-13 两条用例
├── TLS-1-1 格类128比特抗量子算法混合密钥交换.sh
├── … （共 24 个用例脚本）
└── results/
    └── run-YYYYmmdd-HHMMSS-PID/
        ├── summary.tsv            全部用例汇总（run_all.sh 生成）
        └── TLS-1-1/
            ├── commands.log       每条指令、退出码
            ├── output.log         全部终端输出（客户端输出与解析结果）
            ├── summary.txt        步骤级 PASS/FAIL/SKIP 与最终结论
            ├── captures/          *.pcap、tcpdump 日志
            └── analysis/          tshark / tshark_check.sh 解析输出
```

## 服务端固定端点

服务端只需一次性执行 `bash tls-test-scripts/server-endpoints.sh start`（`stop`/`status` 同理），之后测试期间不再登录服务端。

| 端口 | 程序 | 用途 |
|---|---|---|
| 8080 | `.build/server` | 全部非 HQC 组 |
| 8181 | `.build/server_hqc` | 全部 HQC 组（8081 在测试环境被其他服务占用） |
| 8082 | `.build/server -kex X25519,X25519Kyber1024Draft00` | 协商策略（TLS-1-7） |
| 8099 | `.build/tlsbench -mode server` | 性能与并发（TLS-2-1～2-4、2-7） |
| 8111 | `.build/server` + 过期证书 | 证书有效性（TLS-1-10） |

端点日志与 PID 在服务端 `endpoints/<端口>.{log,pid}`。

## 用法（本机）

```sh
# 一条命令跑完全部 24 条（建议 sudo，tcpdump 才能抓包）
sudo bash tls-test-scripts/run_all.sh

# 只跑客户端 22 条，不执行服务端侧两条
RUN_SERVER_SIDE=0 sudo bash tls-test-scripts/run_all.sh

# 单条用例
sudo bash "tls-test-scripts/TLS-1-1 格类128比特抗量子算法混合密钥交换.sh"
```

`run_all.sh` 先跑 22 条客户端用例，再通过 SSH 在服务端执行 TLS-2-5、TLS-1-13，把结果取回到 `$RUN_DIR/server-side/` 并合并进同一份 `summary.tsv`；SSH 不可用时这两条保留为 `SERVER-SIDE`，不影响其余用例。服务端侧用例在服务端以普通用户运行（抓包自动进 user+net namespace），不需要 sudo。

前置条件（本机）：`.build/client`、`.build/client_hqc`、`.build/tlsbench`、`.build/e2e` 已构建，`.build/certs/` 下有 `server_root_cert1.pem`、`other.crt`；`python3`、`tcpdump`、`tshark`、`openssl` 可用（握手解析依赖 tshark）；能直连 `SERVER_HOST` 的 8080/8181/8082/8099/8111。TLS-3-4/3-5 需要 `.build/go/bin/go`。

## 配置

`config.env`（均可用环境变量覆盖）：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `MODE` | `client` | `client`=本机客户端；`server`=服务端侧用例 |
| `SERVER_HOST` | `192.168.2.165` | 服务端地址 |
| `SERVER_PORT` / `SERVER_PORT_HQC` | `8080` / `8181` | 非 HQC、HQC 端点 |
| `SERVER_PORT_POLICY` | `8082` | 协商策略端点 |
| `SERVER_PORT_BENCH` | `8099` | 压测端点 |
| `SERVER_PORT_EXPIRED` | `8111` | 过期证书端点 |
| `CAPTURE_IFACE` | `eno2` | 本机抓包网卡 |
| `RUN_SERVER_SIDE` | `1` | `1`=SSH 执行服务端侧两条；`0`=跳过；`local`=本机执行 |
| `SERVER_SSH` | `xgs-server` | 已配置免密登录的主机别名或 `user@host` |
| `SERVER_DIR` | `/opt/pqc-tls-test` | 服务端部署目录 |
| `PERF_N` / `CONCURRENCY_N` / `LOAD_LOOPS` / `NETEM_N` | `200` / `1000` / `150` / `1000` | 用例规模 |

## 抓包

- 客户端在真实网卡（默认 `eno2`）上按 `host $SERVER_HOST and port <端口>` 过滤，抓包与解析结果即客户端视角证据。
- 需要 root 或 `CAP_NET_RAW`（用 `sudo` 运行整条用例）。**不使用** user+net namespace 回退：命名空间会隔离网络，导致无法访问远端服务端。
- 无抓包权限时，抓包、pcap 解析与 tshark 步骤一律记 SKIP（不会误判为失败），握手/负向/性能断言照常执行；完整验收建议整条用例用 sudo 运行。
- 握手解析使用 `tools/tshark_check.sh`（内部调用 Wireshark 的 `tshark`）：按“协商为期望组的 ServerHello 条数”判定，同一端口混入其它连接不会误判；未安装 tshark 时解析步骤记 SKIP。
- `capture_stop` 停止前等待 2 s，确保 tcpdump 把已到达的报文写入文件（新版 libpcap 按 1 秒块超时交付报文，立即 SIGTERM 会得到空 pcap）；tcpdump 支持时同时加 `--immediate-mode`。

## 结果判读

`summary.txt` 每行一个步骤/断言的 `PASS`、`FAIL`、`SKIP`，末尾给出"合计/通过/失败/跳过"与"结论: PASS|FAIL"；有任一 `FAIL` 即判整条用例 FAIL。`commands.log` 作为测试记录的"输入及操作"栏材料，`captures/` 与 `analysis/` 作为抓包材料。

## 服务端侧用例

TLS-2-5（服务端资源消耗，读服务端进程 CPU/内存）与 TLS-1-13（异构认证，需读服务端日志并移走抗量子私钥）无法在客户端完成，由 `run_all.sh` 自动在服务端执行：

```sh
# 默认：SSH 到 SERVER_SSH，在 SERVER_DIR 下执行并取回结果
sudo bash tls-test-scripts/run_all.sh

# 也可以在服务端手工执行这两条
cd /opt/pqc-tls-test && bash tls-test-scripts/run-server-side.sh
```

- 服务端侧结果落在 `$RUN_DIR/server-side/TLS-2-5/`、`$RUN_DIR/server-side/TLS-1-13/`，与客户端用例同一套文件结构。
- SSH 使用调用者的密钥与主机别名（`sudo` 下会切回 `SUDO_USER` 执行），因此无需在 root 下另配密钥。
- 服务端侧用例在服务端以普通用户执行，tcpdump 无权限时自动进 user+net namespace，不修改服务端环境。

## SKIP 的含义

SKIP 只表示“该步骤缺少工具或不在本轮范围”，**不是失败**，也不影响用例结论（有 FAIL 才是失败）。当前所有 SKIP 及原因：

| 用例 | 跳过的步骤 | 原因 |
|---|---|---|
| TLS-1-8 | tshark 解析 Alert 记录 | 未安装 tshark；解析依赖 tshark，该步骤记 SKIP |
| TLS-1-11 | tshark 检查 Application Data | 未安装 tshark；以客户端解密回显为证 |
| TLS-3-2 | tshark 检查密钥材料不外泄 | 未安装 tshark；以客户端解密回显为证 |
| TLS-3-5 | Windows 实机运行 | 本用例只验证交叉编译，运行需 Windows 机器 |

其它说明：

- `TLS-2-7` 时延注入需要 root 并在客户端出口网卡加 `netem`；无权限时只跑无时延基线并把四档记 SKIP。
- `TLS-3-4`（本机编译并回环运行）、`TLS-3-5`（Windows 交叉编译）按定义在本机完成，不涉及远端端点。
- 性能类规模由 `config.env` 控制，可按机器性能调整。
