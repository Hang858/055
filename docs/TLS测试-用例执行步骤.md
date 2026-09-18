# TLS 协议源码库 · 测试用例执行步骤（可直接复制执行）

> 覆盖 B.1 / B.2 / B.3 的 **TLS-1-1 ~ TLS-3-5** 共 20 条，外加新增用例
> **「混合密钥拼接结构验证」**（依据 RFC 9954）。
>
> 标记说明：**✅ 当前环境即可执行** ／ **⚠️ 需先做一处小改动**（本文已写明改法与原因）。

---

## 0. 一次性准备

### 0.1 环境变量（每个新终端先执行一次）

```sh
export R=/home/hangzhang/work/055                 # 仓库根
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
```

编译产物校验：

```sh
$E2E -h 2>&1 | head -20      # 应列出 -cert/-key/-ca/-addr/-msg/-kex/-showkex
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

### 0.4 抓包与解析（TLS-1-4 / TLS-1-5 / 混合拼接用例）

抓包需要 root 或 `CAP_NET_RAW`；解析脚本 `tools/tls_hello_check.py` 纯标准库、
支持 classic pcap 与 pcapng。

```sh
# 终端C：抓包（tshark 写法；-F pcap 可省略，脚本两种格式都认）
sudo tshark -i lo -f "tcp port 8099" -F pcap -w /tmp/tls.pcap
# 等价写法： sudo tcpdump -i lo -w /tmp/tls.pcap "tcp port 8099"

# 解析（可在抓包结束后执行）
python3 $R/tools/tls_hello_check.py /tmp/tls.pcap --expect X25519Kyber1024Draft00
```

脚本会打印：ClientHello 的 `supported_versions` / `supported_groups` / 每个 `key_share`
的组与长度、ServerHello 的选中组与 `key_share` 长度，并把长度与 RFC 9954 的拼接预期逐项对照。

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
python3 $R/tools/tls_hello_check.py /tmp/tls.pcap

# 方式二：用 tshark 提取字段
tshark -r /tmp/tls.pcap -Y "tls.handshake.type == 1" -T fields \
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
python3 $R/tools/tls_hello_check.py /tmp/tls.pcap --expect SM2Kyber512Draft00

tshark -r /tmp/tls.pcap -Y "tls.handshake.type == 2" -T fields \
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

> ⚠️ 若要验证"双方偏好不同时仍能协商成功"，需要 `-kex` 支持逗号分隔的多组列表
> （见 §4 待补项 ①）；当前 `-kex` 只能指定单组。

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
tshark -r /tmp/tls.pcap -Y "tls.alert_message" -T fields \
  -e tls.alert_message.level -e tls.alert_message.desc
# desc = 70 (protocol_version)
```

**判定**：连接被拒绝 + 告警描述为 `protocol_version`。

> 若要"畸形版本字段"（而非合法但过低的版本），需一个手工构造 ClientHello 的小脚本
> （Python `socket`+`struct` 即可，环境已具备）——见 §4 待补项 ③。

---

### TLS-1-8 无效密钥交换组处理（HelloRetryRequest）⚠️

**现状**：代码里已内置为 HRR 测试准备的 `DummyKex`（`cfkem.go` 中
`DummyKex = CurveID(0xfe33)`，注释即写明 "servers will not support … so we can test
HelloRetryRquest"），但当前 `-kex` 只接受单组，无法构造
"key_share 放不支持的组、supported_groups 里保留 X25519" 这一触发条件。

**待补**（见 §4 待补项 ①）：让 `-kex` 支持逗号分隔，并把 `DummyKex` 加入名字表。补完后：

```sh
# 服务端只支持 X25519；客户端首选 DummyKex（服务端不支持）但 supported_groups 含 X25519
cd $CERT && $E2E ... -kex X25519 -addr localhost:8099              # 服务端
cd $CERT && $E2E ... -kex DummyKex,X25519 -addr localhost:8099     # 客户端
```

**期望结果**：抓包中出现两条 ServerHello，第一条是 HRR（`tls.handshake.random` ==
`cf21ad74…8339c`），且带 `key_share_selected_group = 0x001d`；第二条为正常 ServerHello，
最终协商 X25519。

```sh
tshark -r /tmp/tls.pcap -Y "tls.handshake.type == 2" -T fields \
  -e frame.number -e tls.handshake.random -e tls.handshake.extensions_key_share_selected_group
```

---

### TLS-1-9 证书有效性验证 ⚠️（**当前不通过，必须先改代码**）

**现状**：`tls-hybrid/e2e/test.go:235` 为 `InsecureSkipVerify: true`，且手工校验
`validateCertExpiry` 的调用在 `:293` **被注释掉**；`tls-hybrid/client/client.go` 同样
`InsecureSkipVerify: true`，只在 `:191` 调 `validateCertExpiry`（仅能发现"过期/未生效"，
发现不了"签名错误"）。因此**当前无法通过该用例**。

**待补**（见 §4 待补项 ②）：给 `e2e`/`client` 增加 `-verify-cert` 开关，
打开后使用 `RootCAs` 做标准校验（`InsecureSkipVerify=false`），并额外显式检查有效期。

补完后执行：

```sh
# 1) 造一张过期证书
cd /tmp && openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -keyout expired.key -out expired.crt -subj "/CN=expired.example.com" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
# 让 NotAfter 落在过去（openssl 3 支持 -not_before/-not_after；或用 faketime）
openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -keyout expired.key -out expired.crt -subj "/CN=expired.example.com" \
  -not_before 20240101000000Z -not_after 20240201000000Z \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# 2) 用过期证书启动服务端，客户端开启校验
cd $CERT && $E2E -cert /tmp/expired.crt -key /tmp/expired.key -ca /tmp/expired.crt \
  -addr localhost:8099                                # 服务端
cd $CERT && $E2E -verify-cert -ca /tmp/expired.crt -addr localhost:8099   # 客户端
```

**期望结果**：客户端拒绝，输出 `x509: certificate has expired or is not yet valid`
（或本仓库的 `[安全] 证书验证失败: certificate has expired`），握手失败。

> 另一条更省事的路径：把 §0.3 生成的**有效**证书当作"签名错误"的反例——
> 用另一个 CA 签发的证书去启动服务端，客户端固定 `-ca` 指向正确的 CA，即可验证"签名错误被拒"。

---

### TLS-1-10 加密通信验证 ✅（文本）／⚠️（二进制）

文本数据：

```sh
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -msg "测试文本数据 test text 123" -addr localhost:8099
```

**期望**：`🔒 服务器接收到: 测试文本数据 test text 123` 且 `📩 服务器响应: …`，
说明应用层数据经 `ExportKeyingMaterial` 导出的密钥 + AES-GCM 正确加解密。

二进制数据：需要新增 `-msg-hex` 参数（见 §4 待补项 ④）；补完后：

```sh
cd $CERT && $E2E ... -msg-hex 00ff1020304050607f80 -addr localhost:8099
```

---

## 2. B.2 混合抗量子 TLS 协议性能测试

### TLS-2-1 / TLS-2-2 / TLS-2-3 单连接建立耗时 ✅

用 100 次循环取平均（客户端日志中的 `代码执行时间` 不含进程启动开销，可直接统计）：

```sh
cd $CERT
for KEX in SM2Kyber512Draft00 X25519Kyber512Draft00 X25519Kyber1024Draft00; do
  echo "===== $KEX ====="
  # 终端A 起服务端
  $E2E -cert server_root_cert1.pem -key server_root_key1.pem -ca server_root_cert1.pem \
       -kex $KEX -addr localhost:8099 >/dev/null 2>&1 &
  SRVPID=$!; sleep 1
  # 终端B 侧：用两进程客户端循环 100 次（更接近"重复建立单连接"的表述）
  ( cd $R/tls-hybrid/client
    for i in $(seq 1 100); do $CLI -kex $KEX; done ) 2>&1 \
    | awk '/代码执行时间/{gsub(/[^0-9.]/,"",$2); s+=$2; n++; if($2>mx)mx=$2; if(mn==""||$2<mn)mn=$2}
           END{printf "样本=%d 平均=%.3fms 最小=%.3fms 最大=%.3fms\n", n, s/n, mn, mx}'
  kill $SRVPID 2>/dev/null
done
```

**期望结果**：每次连接均成功，输出形如
`样本=100 平均=4.2ms 最小=3.1ms 最大=12.7ms`。

> ⚠️ 该测法把两次 HTTP 请求也计入；若要**纯握手耗时**，建议加 `tools/tlsbench`
> （进程内 `tls.Dial` 计时，输出 P50/P95）——见 §4 待补项 ⑤。

---

### TLS-2-4 并发多个 TLS 连接建立耗时 ⚠️

**现状**：`hey` / `wrk` / `ab` 均未安装。见 §4 待补项 ⑤（推荐自写 `tools/tlsbench -c N`，
不引入外部依赖）。补完后：

```sh
# 先起服务端
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -kex X25519Kyber1024Draft00 -addr localhost:8099 &
# 并发 50、共 1000 次连接，统计成功率和平均耗时
$R/.build/tlsbench -addr localhost:8099 -kex X25519Kyber1024Draft00 -c 50 -n 1000
```

---

### TLS-2-5 服务器资源消耗 ✅

```sh
# 终端A：服务端（记录 PID）
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -addr localhost:8099 >/tmp/srv.log 2>&1 &
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
sudo tshark -i lo -f "tcp port 8099" -F pcap -w /tmp/tls_hybrid.pcap

# 终端B 发起一次握手（可换任意混合组）
cd $CERT && $E2E -cert server_root_cert1.pem -key server_root_key1.pem \
  -ca server_root_cert1.pem -kex X25519Kyber1024Draft00 -addr localhost:8099

# 解析并断言
python3 $R/tools/tls_hello_check.py /tmp/tls_hybrid.pcap --expect X25519Kyber1024Draft00
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

## 5. 待补项（让 ⚠️ 用例变为 ✅）

| # | 补什么 | 影响的用例 | 预估 |
|---|---|---|---|
| ① | `-kex` 支持逗号分隔多组 + 把 `DummyKex` 加进名字表 | TLS-1-6（严格版）、TLS-1-8 | ~20 行 |
| ② | `e2e`/`client` 增加 `-verify-cert`（`InsecureSkipVerify=false` + RootCAs + 显式有效期检查） | TLS-1-9 | ~15 行 |
| ③ | 手工构造异常 ClientHello 的小脚本（畸形版本号 / 未知组） | TLS-1-7（严格版）、TLS-1-8（替代路线） | ~80 行 |
| ④ | `-msg-hex` 支持二进制应用数据 | TLS-1-10（二进制） | ~10 行 |
| ⑤ | `tools/tlsbench`：进程内 N 次握手计时（均值/P50/P95）+ 并发模式 | TLS-2-1~2-4 | ~120 行 |
| ⑥ | 服务端启动日志把 `CurveID(65078)` 打印成组名（当前是数字，仅影响观感） | 全部握手用例的服务端侧日志 | ~5 行 |
