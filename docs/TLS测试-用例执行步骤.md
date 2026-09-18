# TLS 协议源码库 · 测试用例执行步骤（可直接复制执行）

> 覆盖 B.1 / B.2 / B.3 的 **TLS-1-1 ~ TLS-3-5** 共 20 条，外加新增用例
> **「混合密钥拼接结构验证」**（依据 RFC 9954）。
>
> 全部用例均已可用代码测量；每条都给出可直接复制执行的命令与实测结果。
> 所需工具（`tools/tls_hello_check.py`、`tools/tls_abnormal_hello.py`、`tools/tlsbench`）
> 与参数（`-kex` 多组、`-verify`、`-msg-hex`）已随仓库提供，见 §5。

---

## 0. 一次性准备

### 0.1 环境变量（每个新终端先执行一次）

> **路径约定**：不写死任何绝对路径。先在终端里 `cd` 到**项目根目录**（即本仓库根目录，
> 里面有 `README.md`、`tls-hybrid/`、`pqcert/`、`tools/`、`docs/`、`.build/`），
> 下面的 `$R` 就取当前目录；换机器只要换 `cd` 的目标即可。
> 逐步骤、更细的命令（含多终端标注）见 `docs/测试大纲-输入及操作-细化.md`。

```sh
cd 055                                            # ← 换成你本机的项目目录名（进入项目根目录）
export R=$PWD                                     # 仓库根（= 当前目录）
export GOROOT=$R/.build/go                        # 打补丁的 Linux 版 Go 1.22.12
export PATH=$GOROOT/bin:$PATH
export GOCACHE=$R/.build/gocache GOPATH=$R/.build/gopath
export GOFLAGS=-buildvcs=false GOTOOLCHAIN=local
export E2E=$R/.build/e2e                          # 端到端自测（不含 HQC）
export E2EH=$R/.build/e2e_hqc                     # 端到端自测（含 HQC，需 -tags pq_hqc）
export SRV=$R/.build/server                       # 服务端
export CLI=$R/.build/client                       # 客户端
export CERT=$R/tls-hybrid/e2e                     # 证书目录
```

> `.build/` 目录**不在 git 里**（工具链 + liboqs 约 470MB）。若换机器，先按
> `docs/BUILD.md` A 节重建打补丁的 Go 1.22.12，再按
> `docs/HQC-TLS-最小改造路线.md` §3.1 编译 liboqs。

### 0.2 编译二进制

```sh
cd $R/tls-hybrid/e2e    && go build -o $E2E .            # 端到端（默认，无 HQC）
cd $R/tls-hybrid/server && go build -o $SRV .            # 服务端
cd $R/tls-hybrid/client && go build -o $CLI .            # 客户端

# HQC 版本（需要 cgo + liboqs；只影响带 -tags pq_hqc 的这次构建）
export CGO_ENABLED=1
export CGO_CFLAGS="-I$R/.build/liboqs/include"
export CGO_LDFLAGS="-L$R/.build/liboqs/lib -loqs"
cd $R/tls-hybrid/e2e && go build -tags pq_hqc -o $E2EH .

# 性能测试工具（模块位于 tools/tlsbench/）
cd $R/tools/tlsbench && go build -o $R/.build/tlsbench .
go build -tags pq_hqc -o $R/.build/tlsbench_hqc .   # 需要压测 HQC 组时
```

编译产物校验：

```sh
$E2E -h 2>&1 | head -20            # 应列出 -cert/-key/-ca/-addr/-msg/-msg-hex/-kex/-verify/-showkex
$R/.build/tlsbench -h 2>&1 | head -12
```

### 0.3 ⚠️ 证书：仓库自带的测试证书**已全部过期**

执行测试前必须重新生成，否则两进程路径会被客户端的手工有效期校验拒绝
（日志：`[安全] 证书验证失败: certificate has expired`）。

| 文件 | 到期时间 | 状态 |
|---|---|---|
| `tls-hybrid/server/server_root_cert1.pem` / `.../server_root_key1.pem` | 2026-04-15 | ❌ 已过期 |
| `tls-hybrid/{server,client,e2e}/server.crt`、`server1.crt` | 2025-04-16 | ❌ 已过期 |
| `tls-hybrid/{server,e2e}/server_root_cert.pem` | 2025-04-15 | ❌ 已过期 |

```sh
# 重新生成服务端证书/私钥（有效期 10 年，覆盖同名文件；git checkout -- <文件> 可还原）
cd $R/tls-hybrid/server
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
  -keyout server_root_key1.pem -out server_root_cert1.pem \
  -subj "/C=CN/O=Root Certificate/CN=Root Certificate" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# 校验
openssl x509 -in server_root_cert1.pem -noout -dates -subject
```

> 说明：客户端程序读取的 CA 文件默认为其工作目录下的 `server.crt`，可用 `-ca <文件>`
> 覆盖；`e2e` 用 `-cert/-key/-ca` 三个参数分别指定服务端证书/私钥与信任的 CA。
> 启用 `-verify` 时，服务端证书必须能由 `-ca` 指定的 CA 验证且未过期。

### 0.4 抓包与解析（TLS-1-4 / TLS-1-5 / 混合拼接用例）

抓包需要 root 或 `CAP_NET_RAW`；解析脚本 `tools/tls_hello_check.py` 纯标准库、
支持 classic pcap 与 pcapng。

```sh
# 终端C：抓包（tshark 写法；-F pcap 可省略，脚本两种格式都认）
sudo tshark -i lo -f "tcp port 8099" -F pcap -w $R/.build/tls.pcap
# 等价写法： sudo tcpdump -i lo -w $R/.build/tls.pcap "tcp port 8099"

# 解析（可在抓包结束后执行）
python3 $R/tools/tls_hello_check.py $R/.build/tls.pcap --expect X25519Kyber1024Draft00
```

脚本会打印：ClientHello 的 `supported_versions` / `supported_groups` / 每个 `key_share`
的组与长度、ServerHello 的选中组与 `key_share` 长度，并把长度与 RFC 9954 的拼接预期逐项对照。

异常交互用例（TLS-1-7 / TLS-1-8）另有 `tools/tls_abnormal_hello.py`：手工构造异常
ClientHello 并解析服务端响应，**纯标准库、不需要抓包与 root**，用法见对应用例。

---

## 1. B.1 混合抗量子 TLS 协议功能测试

### TLS-1-1 SM2Kyber512Draft00 密钥交换功能 ✅

**步骤1** 服务端（终端A）：

```sh
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -kex SM2Kyber512Draft00 -addr localhost:8099
```

**步骤2** 客户端（终端B）：

```sh
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -kex SM2Kyber512Draft00 -addr localhost:8099
```

> 两进程版本（对应"服务端程序/客户端程序"写法）：
> 终端A `cd $R/tls-hybrid/server && $SRV -kex SM2Kyber512Draft00`；
> 终端B `cd $R/tls-hybrid/client && $CLI -kex SM2Kyber512Draft00`。
> `e2e` 是单进程内同时起服务端与客户端，便于自动化，二者协议行为一致。

**期望结果**（实测输出）：

```
🔑 使用密钥交换算法: SM2Kyber512Draft00 (混合后量子)
🔒 服务器接收到: Secret quantum-safe message
📩 服务器响应: 量子安全响应: Secret quantum-safe message
✅ 客户端和服务器交互完成。
```

**判定**：日志中出现的组名 == 配置的 `-kex` 值，且交互完成。

---

### TLS-1-2 X25519Kyber512Draft00 密钥交换功能 ✅

把上一条的 `-kex` 换成 `X25519Kyber512Draft00` 即可：

```sh
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -kex X25519Kyber512Draft00 -addr localhost:8099
```

**期望**：`🔑 使用密钥交换算法: X25519Kyber512Draft00 (混合后量子)`（128 比特量子安全等级）。

---

### TLS-1-3 X25519Kyber1024Draft00 密钥交换功能 ✅

```sh
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -kex X25519Kyber1024Draft00 -addr localhost:8099
```

**期望**：`🔑 使用密钥交换算法: X25519Kyber1024Draft00 (混合后量子, 256 比特量子安全等级)`
（实测客户端两进程路径耗时 3.3ms）

---

### TLS-1-4 ClientHello 消息格式验证 ✅

**步骤1** 终端C 开始抓包（见 §0.4）。

**步骤2** 终端A/B 发起一次握手（默认即发送全部 6 个组）：

```sh
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -addr localhost:8099
```

**步骤3** 检查 ClientHello 字段：

```sh
# 方式一：用解析脚本（推荐，直接给出结论与长度断言）
python3 $R/tools/tls_hello_check.py $R/.build/tls.pcap

# 方式二：用 tshark 提取字段
tshark -r $R/.build/tls.pcap -Y "tls.handshake.type == 1" -T fields \
  -E header=y -E occurrence=a -E aggregator=, \
  -e tls.handshake.legacy_version \
  -e tls.handshake.extensions.supported_version \
  -e tls.handshake.extensions_supported_group \
  -e tls.handshake.extensions_key_share_group \
  -e tls.handshake.extensions_key_share_key_exchange_length
```

**期望结果**（实测）：

```
legacy_version = 0x0303（TLS 1.2 兼容值，TLS 1.3 规定）
supported_versions = 0x0304（TLS 1.3）
supported_group = 0xfe34,0xfe30,0xfe36,0xfe37,0x6399,0x001d   ← 恰好 6 个组，按偏好降序
key_share_group = 0xfe34        ← 只为第一个偏好发 key_share
key_share_key_exchange_length = 865      ← 65(SM2 公钥) + 800(Kyber512 公钥)
```

**判定**：ClientHello 含多个受支持的组与混合公钥，长度符合 §4 的拼接表。

---

### TLS-1-5 ServerHello 消息格式验证 ✅

用同一份抓包（步骤同 TLS-1-4）：

```sh
python3 $R/tools/tls_hello_check.py $R/.build/tls.pcap --expect SM2Kyber512Draft00

tshark -r $R/.build/tls.pcap -Y "tls.handshake.type == 2" -T fields \
  -E header=y -E occurrence=a -E aggregator=, \
  -e tls.handshake.extensions_key_share_selected_group \
  -e tls.handshake.extensions_key_share_key_exchange_length \
  -e tls.handshake.extensions.supported_version
```

**期望结果**（实测）：

```
selected_group = 0xfe34(SM2Kyber512Draft00)
key_share_key_exchange_length = 897      ← 129(SM2 密文) + 768(Kyber512 密文)
supported_version = 0x0304
```

**判定**：ServerHello 中选中的组与客户端 offer 的某个组一致，且 key_share 长度 = 经典分量密文
长度 + 抗量子分量密文长度（RFC 9954 §3.2：服务端放各分量的密文）。

---

### TLS-1-6 多密钥交换组协商策略验证 ✅

**步骤1** 服务端与客户端都用默认（全组）配置：

```sh
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -addr localhost:8099
```

**步骤2** 查看协商结果：

```
🔑 使用密钥交换算法: SM2Kyber512Draft00 (混合后量子)
```

**判定**：双方共同支持组中的最优者被选中（实测默认首选 `SM2Kyber512Draft00`）。
用 `tools/tls_hello_check.py` 可同时看到"offer 6 组 / 选中第 1 个"的完整证据。

> **更严格的验证（双方偏好不同）**：`-kex` 支持逗号分隔的多组，顺序即偏好。
>
> ```sh
> # 服务端偏好 [X25519, X25519Kyber1024Draft00]
> cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
>   -ca server_root_cert1.pem -kex X25519,X25519Kyber1024Draft00 -addr localhost:8099 &
> # 客户端偏好 [X25519Kyber768Draft00, X25519]，与服务端的交集只有 X25519
> cd $R/tls-hybrid/client && $CLI -kex X25519Kyber768Draft00,X25519
> ```
>
> **实测**：客户端输出 `Used X25519`；服务端启动日志
> `启用的密钥交换组: [X25519 X25519Kyber1024Draft00]`——即从"双方共同支持"的组中选出了
> X25519（客户端首选的 Kyber768 服务端并不支持）。

---

### TLS-1-7 异常协议版本处理 ✅

用系统 openssl 以 TLS 1.2 连接只允许 TLS 1.3 的服务端：

```sh
# 终端A 起服务端
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -addr localhost:8099

# 终端B
openssl s_client -connect 127.0.0.1:8099 -tls1_2 -brief </dev/null; echo "退出码=$?"
```

**期望结果**：握手失败，服务端返回 `protocol_version` 告警；

```
# openssl 侧
error: ... tlsv1 alert protocol version
退出码=1
```

抓包侧核对告警类型：

```sh
tshark -r $R/.build/tls.pcap -Y "tls.alert_message" -T fields \
  -e tls.alert_message.level -e tls.alert_message.desc
# desc = 70 (protocol_version)
```

**判定**：连接被拒绝 + 告警描述为 `protocol_version`。

> **严格版（畸形版本字段）**：用 `tools/tls_abnormal_hello.py` 构造
> legacy_version=0x0300 且不带 supported_versions 的 ClientHello：
>
> ```sh
> # 终端A 起服务端（只支持 X25519）
> cd $R/tls-hybrid/server && $SRV -kex X25519
> # 终端B
> python3 $R/tools/tls_abnormal_hello.py --addr localhost:8080 --mode bad-version
> python3 $R/tools/tls_abnormal_hello.py --addr localhost:8080 --mode tls12-only
> ```
>
> **实测输出**：
>
> ```
> 服务端响应: ALERT level=2 desc=70(protocol_version)
> 判定: ✅ 通过（期望 alert:protocol_version，实际 alert:protocol_version）
> ```
>
> 另有 `--mode no-common-group`（supported_groups 与服务端无交集）→ 实测
> `ALERT level=2 desc=40(handshake_failure)`。

---

### TLS-1-8 无效密钥交换组处理（HelloRetryRequest）✅

代码内置了专用于 HRR 测试的 `DummyKex`（`cfkem.go` 中 `DummyKex = CurveID(0xfe33)`，
注释即写明 "servers will not support … so we can test HelloRetryRquest"）。
现在 `-kex` 支持逗号分隔的多组，客户端可用 `DummyKex,X25519` 构造触发条件。

**步骤1** 服务端（终端A）只支持 X25519：

```sh
cd $R/tls-hybrid/server && $SRV -kex X25519
```

**步骤2** 客户端（终端B）首选 DummyKex，但 supported_groups 里保留 X25519：

```sh
cd $R/tls-hybrid/client && $CLI -kex DummyKex,X25519
```

**步骤3** 抓包确认（终端C，见 §0.4）：

```sh
python3 $R/tools/tls_hello_check.py $R/.build/tls.pcap
tshark -r $R/.build/tls.pcap -Y "tls.handshake.type == 2" -T fields \
  -e frame.number -e tls.handshake.random -e tls.handshake.extensions_key_share_selected_group
```

**实测结果**：

```
supported_groups(2 个): 0xfe33 DummyKex、0x001d X25519
CH key_share: 组=0xfe33(DummyKex) 长度=32
【ServerHello】共 2 条（含 HRR）
  #1 HelloRetryRequest    ← HRR（random == cf21ad74…8339c）
  #2 ServerHello  key_share = 0x001d(X25519) 长度=32
【结论】最终协商: 0x001d X25519   总判定: ✅ 全部通过
```

客户端日志为 `Used X25519`（HRR 后按服务端要求重发 key_share 并完成握手）。
**另一条不需要真实客户端的路径**：`python3 $R/tools/tls_abnormal_hello.py --mode unknown-group`
→ 实测直接收到 `HelloRetryRequest ... key_share_group=0x001d`。

---

### TLS-1-9 证书有效性验证 ✅

`e2e` 与 `client` 都支持 `-verify`：打开后 `InsecureSkipVerify=false`（标准链校验）
并额外显式校验对端证书有效期；`client` 另可用 `-ca` 指定信任的 CA 文件。

**步骤1** 准备证书：

```sh
mkdir -p $R/.build/certs && cd $R/.build/certs
# 有效证书（服务端用，同时作为客户端信任的 CA）
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
  -keyout fresh.key -out fresh.crt -subj "/C=CN/O=Test/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
# "另一个 CA"，用于制造"签名错误 / 不受信任"场景
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
  -keyout other.key -out other.crt -subj "/C=CN/O=Other/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

**步骤2（过期证书应被拒绝）** 用仓库里已过期的证书启动服务端：

```sh
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -verify -addr localhost:8211
```

**实测输出**：

```
请求失败: ... tls: failed to verify certificate:
x509: certificate has expired or is not yet valid: current time 2026-09-18T15:03:14+08:00
is after 2026-04-15T05:31:01Z
```

**步骤3（签名错误/CA 不匹配应被拒绝）**：

```sh
cd $CERT && $E2E -cert $R/.build/certs/fresh.crt -key $R/.build/certs/fresh.key \
  -ca $R/.build/certs/other.crt -verify -addr localhost:8232
```

**实测输出**：

```
请求失败: ... tls: failed to verify certificate: x509: certificate signed by unknown authority
```

**步骤4（有效证书应通过）**：

```sh
cd $CERT && $E2E -cert $R/.build/certs/fresh.crt -key $R/.build/certs/fresh.key \
  -ca $R/.build/certs/fresh.crt -verify -addr localhost:8231
```

**实测输出**：

```
🔐 证书校验通过（-verify）
🔒 服务器接收到: Secret quantum-safe message
📩 服务器响应: 量子安全响应: Secret quantum-safe message
✅ 客户端和服务器交互完成。
```

> 两进程路径同理：把新证书放到 `tls-hybrid/server/`
> （文件名固定为 `server_root_cert1.pem` / `server_root_key1.pem`）后在该目录启动服务端；
> 客户端 `cd $R/tls-hybrid/client && $CLI -kex X25519Kyber1024Draft00 -verify -ca <新证书>`。
> 实测：有效证书通过（3.1ms）；`-ca` 指向错误证书则报
> `x509: certificate signed by unknown authority`。

---

### TLS-1-10 加密通信验证 ✅（文本与二进制）

文本数据：

```sh
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -msg "测试文本数据 test text 123" -addr localhost:8099
```

**期望**：`🔒 服务器接收到: 测试文本数据 test text 123` 且 `📩 服务器响应: …`，
说明应用层数据经 `ExportKeyingMaterial` 导出的密钥 + AES-GCM 正确加解密。

二进制数据（`-msg-hex`，十六进制输入）：

```sh
cd $CERT && $E2E -cert $R/.build/certs/fresh.crt -key $R/.build/certs/fresh.key \
  -ca $R/.build/certs/fresh.crt -msg-hex 00ff1020304050607080 -addr localhost:8231
```

**实测输出**：

```
🔒 服务器接收到: (二进制 10 字节) 00ff1020304050607080
📩 服务器响应: 量子安全响应: <10 字节原始数据回显>     ← 客户端成功解密
⏱️ 总执行时间: 5.856882ms
```

---

## 2. B.2 混合抗量子 TLS 协议性能测试

### TLS-2-1 / TLS-2-2 / TLS-2-3 单连接建立耗时 ✅

推荐用 `tools/tlsbench`（进程内 `tls.Dial` 计时，**只算握手**，不含进程启动与 HTTP 开销）：

```sh
# 终端A：压测服务端（用仓库自带的证书即可，压测客户端默认不校验证书）
cd $R/tls-hybrid/server
$R/.build/tlsbench -mode server -addr :8099 \
  -cert server_root_cert1.pem -key server_root_key1.pem -kex X25519Kyber1024Draft00 &

# 终端B：逐组重复 200 次单连接，输出 均值/最小/最大/P50/P90/P95/P99
for KEX in SM2Kyber512Draft00 X25519Kyber512Draft00 X25519Kyber1024Draft00; do
  echo "===== $KEX ====="
  $R/.build/tlsbench -mode client -addr localhost:8099 -kex $KEX -n 200
done

# HQC 组（用带 pq_hqc 的版本；服务端也要换成 tlsbench_hqc）
$R/.build/tlsbench_hqc -mode client -addr localhost:8099 -kex X25519HQC-128 -n 100
$R/.build/tlsbench_hqc -mode client -addr localhost:8099 -kex X25519HQC-256 -n 50
```

**实测结果**（本机，单位 ms）：

| 组 | 平均 | 最小 | 最大 | P50 | P95 | P99 |
|---|---|---|---|---|---|---|
| `SM2Kyber512Draft00` | 4.922 | 4.572 | 6.061 | 4.865 | 5.421 | 5.839 |
| `X25519Kyber512Draft00` | 1.964 | 1.813 | 2.770 | 1.935 | 2.189 | 2.691 |
| `X25519Kyber1024Draft00` | 2.048 | 1.891 | 3.147 | 2.014 | 2.272 | 2.567 |
| `X25519HQC-128` | 8.100 | 7.710 | 8.962 | 7.961 | 8.779 | 8.962 |
| `X25519HQC-256` | 35.559 | 34.757 | 40.763 | 35.363 | 36.902 | 40.763 |

> 备选（不新增工具）：两进程客户端循环若干次，统计日志里的 `代码执行时间`
> （不含进程启动开销，但含两次 HTTP 请求）：
>
> ```sh
> ( cd $R/tls-hybrid/client; for i in $(seq 1 100); do $CLI -kex X25519Kyber1024Draft00; done ) 2>&1 \
>   | awk '/代码执行时间/{gsub(/[^0-9.]/,"",$2); s+=$2; n++} END{printf "样本=%d 平均=%.3fms\n", n, s/n}'
> ```

---

### TLS-2-4 并发多个 TLS 连接建立耗时 ✅

```sh
# 终端A：压测服务端
cd $R/tls-hybrid/server
$R/.build/tlsbench -mode server -addr :8099 \
  -cert server_root_cert1.pem -key server_root_key1.pem -kex X25519Kyber1024Draft00 &

# 终端B：并发 50、共 1000 次连接
$R/.build/tlsbench -mode client -addr localhost:8099 -kex X25519Kyber1024Draft00 -c 50 -n 1000
```

**实测结果**：

```
成功 1000 / 失败 0，总墙钟耗时 385ms（2594.3 连接/秒）
握手耗时: 平均=18.906ms 最小=2.945ms 最大=67.171ms P50=18.075ms P90=36.273ms P95=44.968ms P99=60.381ms
```

成功率 100%。并发连接建立能力的采样口径：并发数 `-c`、总次数 `-n` 可按需调整
（例如 `-c 100 -n 5000`）。

---

### TLS-2-5 服务器资源消耗 ✅

```sh
# 终端A：服务端（记录 PID）
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -addr localhost:8099 >$R/.build/srv.log 2>&1 &
SRVPID=$!

# 终端B：制造负载（循环握手）
cd $R/tls-hybrid/client && for i in $(seq 1 200); do $CLI; done

# 终端C：采样 CPU/内存（sysstat 已安装）
pidstat -p $SRVPID 1 20            # 每秒一次，共 20 次：%CPU、RSS
grep -E "VmRSS|VmHWM" /proc/$SRVPID/status
ps -o pid,pcpu,pmem,rss,vsz,etime -p $SRVPID
```

**期望结果**：形成 CPU 使用率与内存占用（RSS/VmHWM）随通信阶段变化的记录；
用 `pidstat` 输出可直接作为测试附件。

---

## 3. B.3 混合抗量子 TLS 协议兼容性测试

### TLS-3-1 协商结果事件记录验证 ✅

`CFEventTLS13NegotiatedKEX` 在 `e2e/test.go` 与 `client/client.go` 均已实现：

```sh
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -kex X25519Kyber768Draft00 -addr localhost:8099
```

**期望**：客户端打印 `🔑 使用密钥交换算法: X25519Kyber768Draft00 (混合后量子)`，
与两端 `-kex` 配置一致。关闭记录可用 `-showkex=false` 作对照。

---

### TLS-3-2 ExportKeyingMaterial 密钥材料导出验证 ✅

```sh
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -kex X25519Kyber1024Draft00 -addr localhost:8099
```

**期望**：双方使用同一 label（`e2e` 用 `quantum_app_key`，两进程版用 `my_app_key`）导出
32 字节密钥材料，并用其做 AES-GCM 加解密：

```
🔒 服务器接收到: Secret quantum-safe message       ← 服务端成功解密客户端密文
📩 服务器响应: 量子安全响应: Secret quantum-safe message  ← 客户端成功解密服务端密文
```

**判定**：两侧均能正确解密，说明导出密钥一致且导出功能可用。

---

### TLS-3-3 X25519 传统密钥交换回退验证 ✅

```sh
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -kex X25519 -addr localhost:8099
```

**期望**：`🔑 使用密钥交换算法: X25519 (传统)`，交互完成。
抓包可见 `key_share` 长度 32（无抗量子分量）。

---

### TLS-3-4 Linux 平台编译与运行验证 ✅

```sh
cd $R/tls-hybrid/server && go build -o $SRV . && file $SRV
cd $R/tls-hybrid/client && go build -o $CLI . && file $CLI
# 运行
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -addr localhost:8099
```

**期望**：`file` 显示 `ELF 64-bit LSB executable, x86-64`；运行后握手与加密通信正常。

---

### TLS-3-5 Windows 目标平台交叉编译验证 ✅

```sh
cd $R/tls-hybrid/server
GOOS=windows GOARCH=amd64 go build -o $R/dist/tls/server/windows_server.exe .
cd $R/tls-hybrid/client
GOOS=windows GOARCH=amd64 go build -o $R/dist/tls/client/windows_client.exe .
file $R/dist/tls/server/windows_server.exe $R/dist/tls/client/windows_client.exe
```

**期望**：`PE32+ executable (console) x86-64, for MS Windows`，编译无错误。

> 注意：交叉编译走**默认构建**（`CGO_ENABLED=0`）。HQC 版本依赖 cgo，交叉编译 Windows
> 需要 mingw-w64 + Windows 版 liboqs，需在 Windows/mingw 环境下构建（本机未装 mingw）。

---

## 4. 新增用例：混合密钥拼接结构验证（RFC 9954）✅

### 依据

**RFC 9954《Hybrid Key Exchange in TLS 1.3》**

- §3.2：`key_exchange` 字段是各分量 `key_exchange` 的**直接拼接**（无额外长度字段），
  顺序必须与 NamedGroup 定义一致；客户端放各分量的**公钥**，服务端放各分量的**密文**。
- §3.3：`concatenated_shared_secret = MyECDH.shared_secret || MyPQKEM.shared_secret`，
  整体送入 TLS 1.3 密钥表的 HKDF-Extract；协议不额外做 KDF；要求各分量**定长**。
- §4：`key_exchange` 上限 2^16-1 字节（HQC-256 的 7277/14453 字节仍在范围内）。

### 测试步骤

```sh
# 终端C 抓包
sudo tshark -i lo -f "tcp port 8099" -F pcap -w $R/.build/tls_hybrid.pcap

# 终端B 发起一次握手（可换任意混合组）
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -kex X25519Kyber1024Draft00 -addr localhost:8099

# 解析并断言
python3 $R/tools/tls_hello_check.py $R/.build/tls_hybrid.pcap --expect X25519Kyber1024Draft00
```

### 期望结果（实测）

```
✅ CH key_share: 组=0xfe36(X25519Kyber1024Draft00) 长度=1600，期望 1600
     ✅ SH key_share: 组=0xfe36(X25519Kyber1024Draft00) 长度=1600，期望 1600
   ✅ 协商组符合预期: X25519Kyber1024Draft00
总判定: ✅ 全部通过
```

### 各组的拼接长度对照（供断言）

| 混合组 | ClientHello key_share | ServerHello key_share | 拼接的共享密钥 |
|---|---|---|---|
| `SM2Kyber512Draft00` | 65 + 800 = **865** | 129 + 768 = **897** | 32 ‖ 32 = 64 |
| `X25519Kyber512Draft00` | 32 + 800 = **832** | 32 + 768 = **800** | 32 ‖ 32 = 64 |
| `X25519Kyber768Draft00` | 32 + 1184 = **1216** | 32 + 1088 = **1120** | 32 ‖ 32 = 64 |
| `X25519Kyber1024Draft00` | 32 + 1568 = **1600** | 32 + 1568 = **1600** | 32 ‖ 32 = 64 |
| `X25519HQC-128` | 32 + 2249 = **2281** | 32 + 4433 = **4465** | 32 ‖ 64 = 96 |
| `X25519HQC-256` | 32 + 7245 = **7277** | 32 + 14421 = **14453** | 32 ‖ 64 = 96 |
| `X25519`（回退） | 32 | 32 | 32 |

> 表中长度均已在本次核对中**实测命中**（HQC 组需先按 §0.2 编译 `-tags pq_hqc` 版本，
> 并用 `$E2EH` 代替 `$E2E` 运行）。

---

## 5. 补充的工具与参数（本次已全部实现并实测）

| # | 内容 | 覆盖用例 | 状态 |
|---|---|---|---|
| ① | `-kex` 支持逗号分隔多组（顺序即偏好）+ `DummyKex` 加入名字表（server/client/e2e） | TLS-1-6（严格版）、TLS-1-8 | ✅ 已实测 |
| ② | `e2e`/`client` 新增 `-verify`（标准链校验 + 显式有效期检查）；`client` 新增 `-ca` | TLS-1-9 | ✅ 已实测（过期/错签被拒、有效通过） |
| ③ | `tools/tls_abnormal_hello.py`：bad-version / tls12-only / unknown-group / no-common-group | TLS-1-7（严格版）、TLS-1-8 | ✅ 四种模式已实测 |
| ④ | `-msg-hex` 支持二进制应用数据 | TLS-1-10（二进制） | ✅ 已实测 |
| ⑤ | `tools/tlsbench`：进程内 N 次握手计时（均值/最小/最大/P50/P90/P95/P99）+ 并发模式 + HQC | TLS-2-1 ~ TLS-2-4 | ✅ 已实测 |
| ⑥ | 服务端启动日志打印组名（原为 `CurveID(65078)`） | 全部握手用例的服务端侧日志 | ✅ 已实测 |

**兼容性说明**：`-verify` 默认关闭、`-kex` 不带参数时启用全部组——与补充前的行为一致，
原有测试命令不受影响。

**工具清单**

| 文件 | 用途 |
|---|---|
| `tools/tls_hello_check.py` | 解析 pcap/pcapng，输出 ClientHello/ServerHello 字段并断言混合拼接长度（RFC 9954） |
| `tools/tls_abnormal_hello.py` | 手工构造异常 ClientHello（版本/组），解析服务端告警或 HRR |
| `tools/tlsbench/` | 握手耗时与并发压测（Go 模块，需用打补丁的 GOROOT 编译） |
