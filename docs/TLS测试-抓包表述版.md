# TLS 协议源码库 · 抗量子密钥交换测试步骤（抓包表述版）

> 表述方式与《SSH 抗量子改造测试步骤》保持一致：**运行 tcpdump 抓包 → 打开 Terminal 终端启动服务端（指定密钥交换算法）→ 打开 Terminal 终端启动客户端（指定同一算法）→ 按键 ctrl+c 停止抓包、使用 wireshark 查看获取的 ".pcap" 数据包**。
>
> 命令均为**项目内相对路径**，执行前先打开 Terminal 终端进入**项目根目录**（即仓库根目录，含 `README.md`、`tls-hybrid/`、`tools/`、`.build/`）。
> 服务端 / 客户端 / 证书的编译与生成见 §0，一次性做完即可。
> 每条用例抓到的 pcap 都直接留在项目根目录，文件名已按用例编号命名。
>
> 抓包统一使用 `sudo tcpdump -i lo -nn -s0 -w <文件名>.pcap <端口过滤>`：`-i lo` 抓本地回环，
> `-nn` 不做主机名/端口名解析，`-s0` 抓完整报文（后量子密钥分片较大，避免被截断），末尾的
> `port <端口>` 是抓包过滤条件，只想看纯 TLS 流量时可去掉或改写。
>
> 每条用例一张表，列为 **序号 / 输入及操作 / 预期结果与评估标准 / 实测结果**；
> 其中「实测结果」列**留空**，由测试人员现场执行后填写（已跑出的参考数据见
> `docs/测试大纲-实测结果填充.md`）。可粘贴版本：`docs/TLS测试-抓包表述版.tsv`
> （制表符分隔 6 列，Word/Excel 直接转表格）。

---

## 0. 一次性准备（只做一次）

1. 打开 Terminal 终端，输入以下指令，进入项目根目录：

   ```sh
   cd 055
   ```

2. 打开 Terminal 终端，输入以下指令，编译服务端、客户端与端到端自测程序：

   ```sh
   export PQROOT=$PWD GOCACHE=$PWD/.build/gocache GOPATH=$PWD/.build/gopath GOFLAGS=-buildvcs=false GOTOOLCHAIN=local
   export PATH=$PQROOT/.build/go/bin:$PATH
   ( cd tls-hybrid/server && go build -o ../../.build/server . )
   ( cd tls-hybrid/client && go build -o ../../.build/client . )
   ( cd tls-hybrid/e2e    && go build -o ../../.build/e2e . )
   ```

3. 打开 Terminal 终端，输入以下指令，生成测试用服务端证书与 CA（仓库自带证书已于 2026-04-15 过期）：

   ```sh
   mkdir -p .build/certs
   ( cd .build/certs && \
     openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
       -keyout server_root_key1.pem -out server_root_cert1.pem \
       -subj "/C=CN/O=Root Certificate/CN=Root Certificate" \
       -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" && \
     openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
       -keyout other.key -out other.crt -subj "/C=CN/O=Other/CN=localhost" \
       -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" )
   ```

4. （可选，但建议做一次）打开 Terminal 终端，输入以下指令，让程序导出 TLS 会话密钥，这样 wireshark 才能解密 TLS 1.3 的加密记录：

   ```sh
   export SSLKEYLOGFILE=$PWD/.build/keys.log
   ```

   用法：把它加在启动命令前面，例如 `SSLKEYLOGFILE=.build/keys.log .build/e2e -cert ... -addr localhost:8099`；
   然后在 wireshark 里设置 **编辑 → 首选项 → Protocols → TLS → (Pre)-Master-Secret log filename**，选择项目根目录下的 `keys.log`。

   > TLS 1.3 只有 ClientHello、ServerHello（含 key_share）是**明文**；`Certificate`、`Finished`、`Alert`
   > 都在握手密钥加密之下，不导出密钥时 wireshark 只能把它们显示为 "Application Data"（记录类型 23）。

---

## B.1 混合抗量子 TLS 协议功能测试

### TLS-1-1　SM2Kyber512Draft00 密钥交换功能测试

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包（只抓 TLS 端口可加 `port 8080`）：`sudo tcpdump -i lo -nn -s0 -w tls-1-1-sm2kyber512.pcap port 8080` | tcpdump 开始监听 lo 回环的 8080 端口（提示 `listening on lo`），后续握手报文被完整记录（`-s0` 不截断） |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 SM2Kyber512Draft00，启动 TLS 服务端：`.build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex SM2Kyber512Draft00` | 服务端启动成功：打印 `启用的密钥交换组: [SM2Kyber512Draft00]` 与 `Starting HTTPS server on :8080`，8080 端口处于监听状态 |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 SM2Kyber512Draft00，启动 TLS 客户端：`.build/client -kex SM2Kyber512Draft00 -ca .build/certs/server_root_cert1.pem` | 客户端与服务端完成 TLS 1.3 握手与一次加密交互，输出 `Used Kyber512sm2`、`Server response: ...`、`代码执行时间: ...` |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-1-sm2kyber512.pcap" 数据包：过滤 `tls.handshake.type == 1` 看 ClientHello（key_share 组 0xfe34、长度 865），过滤 `tls.handshake.type == 2` 看 ServerHello（选中组 0xfe34、长度 897），客户端日志出现 `Used Kyber512sm2`。 命令：`python3 tools/tls_hello_check.py tls-1-1-sm2kyber512.pcap --expect SM2Kyber512Draft00` | 实际协商组为 SM2Kyber512Draft00：ClientHello 的 key_share 组 0xfe34、长度 865（SM2 公钥 65 + Kyber512 公钥 800）；ServerHello 选中组 0xfe34、长度 897（SM2 密文 129 + Kyber512 密文 768）；脚本输出 `总判定: ✅ 全部通过` |  |

### TLS-1-2　X25519Kyber512Draft00 密钥交换功能测试

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-1-2-kyber512.pcap port 8080` | tcpdump 已启动并监听 8080 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber512Draft00，启动 TLS 服务端：`.build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber512Draft00` | 服务端启动成功：`启用的密钥交换组: [X25519Kyber512Draft00]`，8080 端口监听正常 |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber512Draft00，启动 TLS 客户端：`.build/client -kex X25519Kyber512Draft00 -ca .build/certs/server_root_cert1.pem` | 握手成功，输出 `Used X25519Kyber512Draft00`、`Server response: ...`、`代码执行时间: ...` |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-2-kyber512.pcap" 数据包：key_share 组应为 0xfe30（长度 ClientHello 832、ServerHello 800），客户端日志出现 `Used X25519Kyber512Draft00`。 命令：`python3 tools/tls_hello_check.py tls-1-2-kyber512.pcap --expect X25519Kyber512Draft00` | 实际协商组为 X25519Kyber512Draft00（128 比特量子安全等级）：key_share 组 0xfe30、长度 ClientHello 832 / ServerHello 800；脚本 `总判定: ✅ 全部通过` |  |

### TLS-1-3　X25519Kyber1024Draft00 密钥交换功能测试

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-1-3-kyber1024.pcap port 8080` | tcpdump 已启动并监听 8080 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动 TLS 服务端：`.build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber1024Draft00` | 服务端启动成功：`启用的密钥交换组: [X25519Kyber1024Draft00]`，8080 端口监听正常 |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动 TLS 客户端：`.build/client -kex X25519Kyber1024Draft00 -ca .build/certs/server_root_cert1.pem` | 握手成功，输出 `Used X25519Kyber1024Draft00 (256 比特量子安全等级)`、`Server response: ...` |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-3-kyber1024.pcap" 数据包：key_share 组应为 0xfe36（长度 ClientHello 1600、ServerHello 1600），客户端日志出现 `Used X25519Kyber1024Draft00 (256 比特量子安全等级)`。 命令：`python3 tools/tls_hello_check.py tls-1-3-kyber1024.pcap --expect X25519Kyber1024Draft00` | 实际协商组为 X25519Kyber1024Draft00（256 比特量子安全等级）：key_share 组 0xfe36、长度 ClientHello 1600 / ServerHello 1600；脚本 `总判定: ✅ 全部通过` |  |

### TLS-1-4　ClientHello 消息格式验证

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-1-4-clienthello.pcap port 8099` | tcpdump 已启动并监听 8099 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定启用全部密钥交换算法，启动 TLS 服务端与客户端（端到端自测，单条命令同时起两端）：`.build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -addr localhost:8099` | 端到端握手完成：输出 `✅ 客户端和服务器交互完成。` |  |
| 3. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-4-clienthello.pcap" 数据包：过滤 `tls.handshake.type == 1`，展开 `supported_versions`（TLS 1.3）、`supported_groups`（6 个组）、`key_share`（首组 0xfe34、长度 865）。 命令：`python3 tools/tls_hello_check.py tls-1-4-clienthello.pcap` | ClientHello 字段符合 TLS 1.3 与 RFC 9954：legacy_version=0x0303、supported_versions=TLS 1.3、supported_groups 6 个（0xfe34、0xfe30、0xfe36、0xfe37、0x6399、0x001d）、CH key_share 组 0xfe34 长度 865；脚本 `总判定: ✅ 全部通过` |  |

### TLS-1-5　ServerHello 消息格式验证

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 复用 TLS-1-4 抓到的 "tls-1-4-clienthello.pcap"；如需重新抓包，按 TLS-1-4 步骤 1~2 再执行一次。 | pcap 中存在 1 条 ServerHello，可直接用于本用例判读 |  |
| 2. | 按键 ctrl+c 停止抓包后，使用 wireshark 打开该数据包：过滤 `tls.handshake.type == 2`，查看 ServerHello 的 `supported_versions`（0x0304）、`cipher_suite`（0x1301）、`key_share` 选中组 0xfe34 且长度 897。 命令：`python3 tools/tls_hello_check.py tls-1-4-clienthello.pcap --expect SM2Kyber512Draft00` | ServerHello 字段正确：选中版本 TLS 1.3（0x0304）、cipher_suite=0x1301、SH key_share 选中组 0xfe34 长度 897；脚本 `✅ 协商组符合预期`、`总判定: ✅ 全部通过` |  |

### TLS-1-6　多密钥交换组协商策略验证

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-1-6-negotiation.pcap port 8080` | tcpdump 已启动并监听 8080 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定优先级为 X25519、X25519Kyber1024Draft00，启动 TLS 服务端：`.build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519,X25519Kyber1024Draft00` | 服务端启动成功，日志列出服务端优先级 `[X25519 X25519Kyber1024Draft00]` |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定优先级为 X25519Kyber768Draft00、X25519，启动 TLS 客户端：`.build/client -kex X25519Kyber768Draft00,X25519 -ca .build/certs/server_root_cert1.pem` | 双方偏好不同仍握手成功，客户端输出 `Used X25519` 并完成加密交互 |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-6-negotiation.pcap" 数据包：ClientHello 的 supported_groups 顺序与 ServerHello 的选中组应满足"服务端偏好优先、且双方都支持"，本例最终选中 0x001d（X25519）。 命令：`python3 tools/tls_hello_check.py tls-1-6-negotiation.pcap --expect X25519` | 最终协商 0x001d X25519（客户端首选的 Kyber768 服务端不支持，按服务端偏好落到双方共同支持的 X25519），符合服务端偏好优先的协商策略；脚本 `总判定: ✅ 全部通过` |  |

### TLS-1-7　异常协议版本处理

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-1-7-abnormal.pcap port 8080` | tcpdump 已启动并监听 8080 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519，启动 TLS 服务端（仅支持 TLS 1.3）：`.build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519` | 服务端启动成功：`启用的密钥交换组: [X25519]`，仅支持 TLS 1.3 |  |
| 3. | 打开 Terminal 终端，输入以下指令，用 TLS 1.2 发起连接（预期被拒绝），并构造畸形版本号与无共同组的 ClientHello：`openssl s_client -connect 127.0.0.1:8080 -tls1_2 -brief </dev/null`；`python3 tools/tls_abnormal_hello.py --addr localhost:8080 --mode bad-version`；`python3 tools/tls_abnormal_hello.py --addr localhost:8080 --mode no-common-group` | 三种异常均被正确拒绝：TLS 1.2 连接输出 `tlsv1 alert protocol version`（alert 70）、退出码 1；bad-version 输出 `ALERT level=2 desc=70(protocol_version)`、`判定: ✅ 通过`；no-common-group 输出 `desc=40(handshake_failure)`、`判定: ✅ 通过` |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-7-abnormal.pcap" 数据包：过滤 `tls.alert_message`，应看到 `Alert (Level: Fatal, Description: Protocol Version)`（desc=70），无共同组时看到 `Handshake Failure`（desc=40）。 命令：`tshark -r tls-1-7-abnormal.pcap -Y "tls.alert_message" -T fields -e tls.alert_message.level -e tls.alert_message.desc` | 报文层面确认异常处理：`tls.alert_message` 可见 `level=2(fatal) desc=70(protocol_version)`（无共同组时为 `desc=40(handshake_failure)`），且没有任何应用数据 |  |

### TLS-1-8　无效密钥交换组处理（HelloRetryRequest）

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-1-8-hrr.pcap port 8080` | tcpdump 已启动并监听 8080 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519，启动 TLS 服务端：`.build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519` | 服务端启动成功：`启用的密钥交换组: [X25519]` |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定首选密钥交换算法为服务端不支持的 DummyKex、并保留 X25519，启动 TLS 客户端：`.build/client -kex DummyKex,X25519 -ca .build/certs/server_root_cert1.pem` | 服务端先回 HelloRetryRequest 要求 X25519，客户端按其要求重发 key_share 后握手成功，输出 `Used X25519` |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-8-hrr.pcap" 数据包：应看到第 1 条 ServerHello 的 random 为 HelloRetryRequest 固定值（`cf21ad74…8339c`），第 2 条 ServerHello 选中 0x001d（X25519），随后握手正常完成。 命令：`python3 tools/tls_hello_check.py tls-1-8-hrr.pcap` | 第 1 条 ServerHello 为 HelloRetryRequest（random 为固定值 cf21ad74…8339c），第 2 条 ServerHello 选中组 0x001d、长度 32；脚本输出 `【ServerHello】共 2 条（含 HRR）`、`【结论】最终协商: 0x001d X25519`，说明服务端能正确处理无效密钥交换组 |  |

### TLS-1-9　证书有效性验证

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-1-9-cert.pcap port 8211 or port 8212 or port 8231` | tcpdump 已启动并监听 8211 / 8212 / 8231 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，分别用"过期证书""有效证书 + 无关 CA""有效证书 + 对应 CA"启动 TLS 服务端与客户端（端到端自测，客户端加 `-verify` 打开证书链校验）：`.build/e2e -cert tls-hybrid/server/server_root_cert1.pem -key tls-hybrid/server/server_root_key1.pem -ca tls-hybrid/server/server_root_cert1.pem -verify -addr localhost:8211`；`.build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/other.crt -verify -addr localhost:8212`；`.build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -verify -addr localhost:8231` | 三种场景结果符合预期：过期证书 → `x509: certificate has expired or is not yet valid`；无关 CA → `x509: certificate signed by unknown authority`；有效证书 → `🔐 证书校验通过（-verify）`并完成加解密交互 |  |
| 3. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-9-cert.pcap" 数据包：；三条连接都能看到**明文**的 ClientHello 与 ServerHello；；端口 8211（过期证书）、8212（无关 CA）：服务端随后发出加密的 Certificate 等记录，客户端校验失败，回一条 19 字节的**加密 Alert**（`bad_certificate`）后断开，整条连接没有任何 Application Data；；端口 8231（有效证书）：握手完成后出现 Application Data 记录； 命令：`tshark -r tls-1-9-cert.pcap -Y "tcp.port == 8211" -T fields -e ip.src -e tcp.srcport -e tls.record.content_type` | 报文层面：8211、8212 两条连接在服务端发出 Certificate 后即终止（无 Application Data），客户端回一条 19 字节的**加密** Alert；8231 连接握手完成并出现 Application Data |  |
| 4. | 若已按 §0 步骤 4 导出密钥日志（`SSLKEYLOGFILE=.build/keys.log`），在 wireshark 里配置好 (Pre)-Master-Secret 后重新打开该数据包，即可看到**明文**的 `Certificate`、`Finished`，以及客户端返回的 `Alert (Level: Fatal, Description: Bad Certificate)`；对应客户端日志分别是 `x509: certificate has expired or is not yet valid`、`x509: certificate signed by unknown authority` 和 `🔐 证书校验通过（-verify）`。 | 配置 (Pre)-Master-Secret 后可看到明文的 `Certificate`、`Finished` 与 `Alert (Level: Fatal, Description: Bad Certificate)`，与客户端日志一致 |  |

### TLS-1-10　加密通信验证

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-1-10-appdata.pcap port 8231` | tcpdump 已启动并监听 8231 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，启动 TLS 服务端与客户端，客户端发送文本数据：`.build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -msg "测试文本数据 test text 123" -addr localhost:8231` | 文本数据收发一致：服务端打印 `🔒 服务器接收到: 测试文本数据 test text 123`，客户端打印 `📩 服务器响应: 量子安全响应: 测试文本数据 test text 123` |  |
| 3. | 打开 Terminal 终端，输入以下指令，改为发送二进制数据：`.build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -msg-hex 00ff1020304050607080 -addr localhost:8231` | 二进制数据收发一致：服务端打印 `🔒 服务器接收到: (二进制 10 字节) 00ff1020304050607080` |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-10-appdata.pcap" 数据包：握手完成后应只看到 `Application Data`（内容为密文，抓包中看不到明文），而服务端日志能打印出与发送内容一致的原文；若按 §0 步骤 4 导出了密钥日志，wireshark 配置 (Pre)-Master-Secret 后可直接看到解密的 `测试文本数据 test text 123` 与二进制 `00ff1020304050607080`。 命令：`tshark -r tls-1-10-appdata.pcap -c 20 -Y "tls.record.content_type == 23"` | 抓包中只有 Application Data（密文），看不到明文；导出密钥后可解出与发送内容逐字节一致的原文，说明应用数据经导出密钥 + AES-GCM 正确加解密 |  |

## B.2 混合抗量子 TLS 协议性能测试

### TLS-2-1　SM2Kyber512Draft00 单连接建立耗时

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-2-1-sm2kyber512-perf.pcap port 8099` | tcpdump 已启动并监听 8099 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 SM2Kyber512Draft00，启动压测服务端：`.build/tlsbench -mode server -addr :8099 -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex SM2Kyber512Draft00` | 压测服务端启动成功：`tlsbench 服务端监听 :8099，密钥交换组: [SM2Kyber512Draft00]` |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 SM2Kyber512Draft00，启动压测客户端，重复建立 200 次连接：`.build/tlsbench -mode client -addr localhost:8099 -kex SM2Kyber512Draft00 -n 200` | 200 次建连全部成功：`成功 200 / 失败 0`，并给出平均/最小/最大/P50/P90/P95/P99 建连耗时（实测平均约 4.9ms，记录实际值） |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-2-1-sm2kyber512-perf.pcap" 数据包：可数出 200 组 ClientHello/ServerHello；客户端统计行给出成功率与平均、P50/P90/P95/P99 建连耗时（实测成功率 200/200、平均约 4.9ms）。 | 抓包中可数出 200 组 ClientHello/ServerHello，key_share 组均为 0xfe34，说明统计结果来自真实握手 |  |

### TLS-2-2　X25519Kyber512Draft00 单连接建立耗时

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-2-2-kyber512-perf.pcap port 8099` | tcpdump 已启动并监听 8099 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber512Draft00，启动压测服务端：`.build/tlsbench -mode server -addr :8099 -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber512Draft00` | 压测服务端启动成功：`密钥交换组: [X25519Kyber512Draft00]` |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber512Draft00，启动压测客户端，重复建立 200 次连接：`.build/tlsbench -mode client -addr localhost:8099 -kex X25519Kyber512Draft00 -n 200` | 200 次建连全部成功：`成功 200 / 失败 0`，实测平均建连约 2.0ms |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-2-2-kyber512-perf.pcap" 数据包：key_share 组均为 0xfe30；客户端统计行给出成功率 200/200 与建连耗时（实测平均约 2.0ms）。 | 抓包中 key_share 组均为 0xfe30，与用例算法一致 |  |

### TLS-2-3　X25519Kyber1024Draft00 单连接建立耗时

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-2-3-kyber1024-perf.pcap port 8099` | tcpdump 已启动并监听 8099 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动压测服务端：`.build/tlsbench -mode server -addr :8099 -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber1024Draft00` | 压测服务端启动成功：`密钥交换组: [X25519Kyber1024Draft00]` |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动压测客户端，重复建立 200 次连接：`.build/tlsbench -mode client -addr localhost:8099 -kex X25519Kyber1024Draft00 -n 200` | 200 次建连全部成功：`成功 200 / 失败 0`，实测平均建连约 2.0ms |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-2-3-kyber1024-perf.pcap" 数据包：key_share 组均为 0xfe36；客户端统计行给出成功率 200/200 与建连耗时（实测平均约 2.0ms）。 | 抓包中 key_share 组均为 0xfe36，与用例算法一致 |  |

### TLS-2-4　并发多个 TLS 连接建立耗时

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-2-4-concurrency.pcap port 8099` | tcpdump 已启动并监听 8099 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动压测服务端：`.build/tlsbench -mode server -addr :8099 -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber1024Draft00` | 压测服务端启动成功：`密钥交换组: [X25519Kyber1024Draft00]` |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，以 50 并发发起 1000 次连接：`.build/tlsbench -mode client -addr localhost:8099 -kex X25519Kyber1024Draft00 -c 50 -n 1000` | 并发连接全部成功：`成功 1000 / 失败 0`，并给出总耗时、连接速率（实测约 2594 连接/秒）与 P50/P90/P95/P99 分位耗时 |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-2-4-concurrency.pcap" 数据包：可见大量并发 ClientHello；客户端统计行给出成功率 1000/1000、总耗时与连接速率（实测约 2594 连接/秒）及 P50/P90/P95/P99 分位耗时。 | 抓包中可见大量并发 ClientHello，成功数与耗时统计与客户端输出一致 |  |

### TLS-2-5　服务器资源消耗

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动压测服务端并记下进程号：`.build/tlsbench -mode server -addr :8099 -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber1024Draft00 & echo "服务端PID=$!"` | 服务端启动成功并打印真实进程号，例如 `服务端PID=257`（`$!` 即 tlsbench 进程本身） |  |
| 2. | 打开 Terminal 终端，输入以下指令，采样空载时的 CPU 与内存占用（把 `<PID>` 换成上一步输出的进程号）：`pidstat -p <PID> 1 5`；`grep VmRSS /proc/<PID>/status; grep Threads /proc/<PID>/status` | 空载资源：%CPU 接近 0、RSS≈6.8MB、Threads≈6 |  |
| 3. | 打开 Terminal 终端，输入以下指令，持续发起连接制造负载：`for i in $(seq 1 150); do .build/tlsbench -mode client -addr localhost:8099 -kex X25519Kyber1024Draft00 -n 20 >/dev/null 2>&1; done` | 客户端持续建连，服务端进入通信阶段（循环执行期间有稳定负载） |  |
| 4. | 负载进行中，打开 Terminal 终端，输入以下指令，再次采样通信阶段的 CPU、内存与线程数：`pidstat -p <PID> 1 5`；`grep VmRSS /proc/<PID>/status; grep VmHWM /proc/<PID>/status; grep Threads /proc/<PID>/status`；`ps -o pid,pcpu,pmem,rss,vsz,etime -p <PID>` | 负载阶段资源：%CPU≈82%（usr≈77%、sys≈5.5%）、RSS≈12.6MB、VmHWM≈12.7MB、Threads≈12；与空载对比可见资源随负载上升且无持续增长 |  |
| 5. | 使用 wireshark 无需抓包即可；在负载过程中另开终端用 `sudo tcpdump -i lo -nn -s0 -w tls-2-5-load.pcap port 8099` 抓 10 秒，可看到持续的双向 Application Data。测试结束后在前一步的终端按 ctrl+c 或用 `kill <PID>` 停止服务端（实测：空载 %CPU≈0、RSS≈6.8MB、线程 6；负载 %CPU≈82%、RSS≈12.6MB、VmHWM≈12.7MB、线程 12）。 | 抓包中可见持续的双向 Application Data；停止后服务端进程退出、8099 端口释放 |  |

## B.3 混合抗量子 TLS 协议兼容性测试

### TLS-3-1　协商结果事件记录验证

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-3-1-negotiatedkex.pcap port 8080` | tcpdump 已启动并监听 8080 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber768Draft00，启动 TLS 服务端：`.build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber768Draft00` | 服务端启动成功：`启用的密钥交换组: [X25519Kyber768Draft00]` |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber768Draft00，启动 TLS 客户端（协商结果由 `CFEventTLS13NegotiatedKEX` 事件打印）：`.build/client -kex X25519Kyber768Draft00 -ca .build/certs/server_root_cert1.pem` | 客户端输出 `Used X25519Kyber768Draft00`（由 CFEventTLS13NegotiatedKEX 事件打印），与服务端 `-kex` 配置一致 |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-3-1-negotiatedkex.pcap" 数据包：ServerHello 选中组 0x6399（X25519Kyber768Draft00），与客户端打印的 `Used X25519Kyber768Draft00` 一致。 命令：`python3 tools/tls_hello_check.py tls-3-1-negotiatedkex.pcap --expect X25519Kyber768Draft00` | 抓包中 ServerHello 选中组 0x6399（X25519Kyber768Draft00），与客户端事件记录一致，证明协商结果被正确记录 |  |

### TLS-3-2　TLS ExportKeyingMaterial 密钥材料导出验证

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-3-2-keyingmaterial.pcap port 8231` | tcpdump 已启动并监听 8231 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动 TLS 服务端与客户端，双方用导出密钥收发数据：`.build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -kex X25519Kyber1024Draft00 -addr localhost:8231` | 握手完成且密钥导出成功：服务端 `🔒 服务器接收到: Secret quantum-safe message`，客户端 `📩 服务器响应: 量子安全响应: Secret quantum-safe message` |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定发送自定义内容以复核：`.build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -kex X25519Kyber1024Draft00 -msg "hello-keying-material" -addr localhost:8231` | 服务端打印内容与 `-msg` 指定的一致（`hello-keying-material`），说明双方用同一份导出密钥完成加解密 |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-3-2-keyingmaterial.pcap" 数据包：导出的密钥材料不出现在报文中（仅由双方各自计算），报文里只有密文的 Application Data；两端日志显示收发内容一致。 命令：`tshark -r tls-3-2-keyingmaterial.pcap -c 20 -Y "tls.record.content_type == 23"` | 导出的密钥材料本身不出现在报文中（由双方各自用 ExportKeyingMaterial 计算），抓包中只有密文的 Application Data |  |

### TLS-3-3　X25519 传统密钥交换回退验证

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-3-3-fallback.pcap port 8080` | tcpdump 已启动并监听 8080 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519（仅传统算法），启动 TLS 服务端：`.build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519` | 服务端启动成功：`启用的密钥交换组: [X25519]` |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519，启动 TLS 客户端：`.build/client -kex X25519 -ca .build/certs/server_root_cert1.pem` | 握手成功并完成加密交互，输出 `Used X25519` |  |
| 4. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-3-3-fallback.pcap" 数据包：key_share 组为 0x001d、长度 32（无抗量子分量），客户端日志出现 `Used X25519`。 命令：`python3 tools/tls_hello_check.py tls-3-3-fallback.pcap --expect X25519` | key_share 为 0x001d、长度 32（无抗量子分量），说明没有可用抗量子组时可回退到传统 X25519；脚本 `总判定: ✅ 全部通过` |  |

### TLS-3-4　Linux 平台编译与运行验证

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 打开 Terminal 终端，输入以下指令，交叉编译（同平台编译）出 Linux 服务端与客户端：`( cd tls-hybrid/server && go build -o ../../dist/tls/server/linux_server . )`；`( cd tls-hybrid/client && go build -o ../../dist/tls/client/linux_client . )`；`file dist/tls/server/linux_server dist/tls/client/linux_client` | 编译成功、无报错；`file` 输出 `ELF 64-bit LSB executable, x86-64` |  |
| 2. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-3-4-linux.pcap port 8080` | tcpdump 已启动并监听 8080 端口 |  |
| 3. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，用刚编译的产物启动 TLS 服务端：`dist/tls/server/linux_server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber1024Draft00` | dist 产物启动成功：`Starting HTTPS server on :8080`，8080 端口监听正常 |  |
| 4. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，用刚编译的产物启动 TLS 客户端：`dist/tls/client/linux_client -kex X25519Kyber1024Draft00 -ca .build/certs/server_root_cert1.pem` | 握手与加密通信成功：`Used X25519Kyber1024Draft00 (256 比特量子安全等级)`、`Server response: ...` |  |
| 5. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-3-4-linux.pcap" 数据包：完成 TLS 1.3 握手（key_share 组 0xfe36），客户端日志出现 `Used X25519Kyber1024Draft00 (256 比特量子安全等级)`。 | 抓包中 key_share 组为 0xfe36、长度 1600，说明 dist 产物功能与源码直接编译一致 |  |

### TLS-3-5　Windows 目标平台交叉编译验证

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 打开 Terminal 终端，输入以下指令，交叉编译出 Windows 服务端：`( cd tls-hybrid/server && GOOS=windows GOARCH=amd64 go build -o ../../dist/tls/server/windows_server.exe . )` | 生成 `dist/tls/server/windows_server.exe`，编译无报错 |  |
| 2. | 打开 Terminal 终端，输入以下指令，交叉编译出 Windows 客户端：`( cd tls-hybrid/client && GOOS=windows GOARCH=amd64 go build -o ../../dist/tls/client/windows_client.exe . )` | 生成 `dist/tls/client/windows_client.exe`，编译无报错 |  |
| 3. | 打开 Terminal 终端，输入以下指令，查看产物文件类型（应为 PE32+ x86-64，即 Windows 可执行文件）：`file dist/tls/server/windows_server.exe dist/tls/client/windows_client.exe` | `file` 输出 `PE32+ executable (console) x86-64, for MS Windows`，两个文件均存在且非空，交叉编译成功 |  |
| 4. | 本条为交叉编译验证，不产生抓包；如需在 Windows 上运行验证，把上述两个 `.exe` 与 `.build/certs/` 下的证书一起拷到 Windows 机器，按 TLS-1-1 的步骤 2、3 运行并抓包。 | 以交叉编译产物为判据（本条不产生抓包）；如需运行验证，在 Windows 上重复 TLS-1-1 步骤 2、3 并抓包，结果应与 Linux 一致 |  |

## 附：新增用例

### TLS-1-11　混合密钥拼接结构验证（依据 RFC 9954）

| 序号 | 输入及操作 | 预期结果与评估标准 | 实测结果 |
|---|---|---|---|
| 1. | 输入以下指令，运行 tcpdump，监听抓包：`sudo tcpdump -i lo -nn -s0 -w tls-1-11-hybrid.pcap port 8099` | tcpdump 已启动并监听 8099 端口 |  |
| 2. | 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动 TLS 服务端与客户端：`.build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -kex X25519Kyber1024Draft00 -addr localhost:8099` | 握手完成：输出 `✅ 客户端和服务器交互完成。` |  |
| 3. | 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-11-hybrid.pcap" 数据包：ClientHello/ServerHello 的 key_share 均为 1600 字节，即 X25519 公钥（32 字节）后直接拼接 Kyber1024 公钥/密文（1568 字节），中间没有长度字段。 命令：`python3 tools/tls_hello_check.py tls-1-11-hybrid.pcap --expect X25519Kyber1024Draft00` | CH/SH 的 key_share 均为 1600 字节 = X25519 公钥/密文 32 字节 + Kyber1024 公钥/密文 1568 字节，中间没有长度字段，符合 RFC 9954 §3.2 的直接拼接要求；脚本 `总判定: ✅ 全部通过` |  |
| 4. | 其余混合组按步骤 1~3 重复，只改 `-kex` 与 `--expect` 的组名（HQC 组需把 `.build/e2e` 换成 `.build/e2e_hqc`，组名写 `X25519HQC-128` / `X25519HQC-256`），各组的 key_share 长度（ClientHello/ServerHello）应依次为：SM2Kyber512Draft00 = 865/897，X25519Kyber512Draft00 = 832/800，X25519Kyber768Draft00 = 1216/1120，X25519Kyber1024Draft00 = 1600/1600，X25519HQC-128 = 2281/4465，X25519HQC-256 = 7277/14453。 | 其余各组长度依次命中 865/897、832/800、1216/1120、1600/1600、2281/4465、7277/14453，且均小于 65535 字节（RFC 9954 §4 的 2^16-1 上限） |  |
