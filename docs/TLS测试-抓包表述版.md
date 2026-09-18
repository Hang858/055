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

1. 输入以下指令，运行 tcpdump，监听抓包（只抓 TLS 端口可加 `port 8080`）：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-1-1-sm2kyber512.pcap port 8080
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 SM2Kyber512Draft00，启动 TLS 服务端：

   ```sh
   .build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex SM2Kyber512Draft00
   ```

3. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 SM2Kyber512Draft00，启动 TLS 客户端：

   ```sh
   .build/client -kex SM2Kyber512Draft00 -ca .build/certs/server_root_cert1.pem
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-1-sm2kyber512.pcap" 数据包：过滤 `tls.handshake.type == 1` 看 ClientHello（key_share 组 0xfe34、长度 865），过滤 `tls.handshake.type == 2` 看 ServerHello（选中组 0xfe34、长度 897），客户端日志出现 `Used Kyber512sm2`。

   ```sh
   python3 tools/tls_hello_check.py tls-1-1-sm2kyber512.pcap --expect SM2Kyber512Draft00
   ```

### TLS-1-2　X25519Kyber512Draft00 密钥交换功能测试

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-1-2-kyber512.pcap port 8080
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber512Draft00，启动 TLS 服务端：

   ```sh
   .build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber512Draft00
   ```

3. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber512Draft00，启动 TLS 客户端：

   ```sh
   .build/client -kex X25519Kyber512Draft00 -ca .build/certs/server_root_cert1.pem
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-2-kyber512.pcap" 数据包：key_share 组应为 0xfe30（长度 ClientHello 832、ServerHello 800），客户端日志出现 `Used X25519Kyber512Draft00`。

   ```sh
   python3 tools/tls_hello_check.py tls-1-2-kyber512.pcap --expect X25519Kyber512Draft00
   ```

### TLS-1-3　X25519Kyber1024Draft00 密钥交换功能测试

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-1-3-kyber1024.pcap port 8080
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动 TLS 服务端：

   ```sh
   .build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber1024Draft00
   ```

3. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动 TLS 客户端：

   ```sh
   .build/client -kex X25519Kyber1024Draft00 -ca .build/certs/server_root_cert1.pem
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-3-kyber1024.pcap" 数据包：key_share 组应为 0xfe36（长度 ClientHello 1600、ServerHello 1600），客户端日志出现 `Used X25519Kyber1024Draft00 (256 比特量子安全等级)`。

   ```sh
   python3 tools/tls_hello_check.py tls-1-3-kyber1024.pcap --expect X25519Kyber1024Draft00
   ```

### TLS-1-4　ClientHello 消息格式验证

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-1-4-clienthello.pcap port 8099
   ```

2. 打开 Terminal 终端，输入以下指令，指定启用全部密钥交换算法，启动 TLS 服务端与客户端（端到端自测，单条命令同时起两端）：

   ```sh
   .build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -addr localhost:8099
   ```

3. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-4-clienthello.pcap" 数据包：过滤 `tls.handshake.type == 1`，展开 `supported_versions`（TLS 1.3）、`supported_groups`（6 个组）、`key_share`（首组 0xfe34、长度 865）。

   ```sh
   python3 tools/tls_hello_check.py tls-1-4-clienthello.pcap
   ```

### TLS-1-5　ServerHello 消息格式验证

1. 复用 TLS-1-4 抓到的 "tls-1-4-clienthello.pcap"；如需重新抓包，按 TLS-1-4 步骤 1~2 再执行一次。

2. 按键 ctrl+c 停止抓包后，使用 wireshark 打开该数据包：过滤 `tls.handshake.type == 2`，查看 ServerHello 的 `supported_versions`（0x0304）、`cipher_suite`（0x1301）、`key_share` 选中组 0xfe34 且长度 897。

   ```sh
   python3 tools/tls_hello_check.py tls-1-4-clienthello.pcap --expect SM2Kyber512Draft00
   ```

### TLS-1-6　多密钥交换组协商策略验证

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-1-6-negotiation.pcap port 8080
   ```

2. 打开 Terminal 终端，输入以下指令，指定优先级为 X25519、X25519Kyber1024Draft00，启动 TLS 服务端：

   ```sh
   .build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519,X25519Kyber1024Draft00
   ```

3. 打开 Terminal 终端，输入以下指令，指定优先级为 X25519Kyber768Draft00、X25519，启动 TLS 客户端：

   ```sh
   .build/client -kex X25519Kyber768Draft00,X25519 -ca .build/certs/server_root_cert1.pem
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-6-negotiation.pcap" 数据包：ClientHello 的 supported_groups 顺序与 ServerHello 的选中组应满足"服务端偏好优先、且双方都支持"，本例最终选中 0x001d（X25519）。

   ```sh
   python3 tools/tls_hello_check.py tls-1-6-negotiation.pcap --expect X25519
   ```

### TLS-1-7　异常协议版本处理

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-1-7-abnormal.pcap port 8080
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519，启动 TLS 服务端（仅支持 TLS 1.3）：

   ```sh
   .build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519
   ```

3. 打开 Terminal 终端，输入以下指令，用 TLS 1.2 发起连接（预期被拒绝），并构造畸形版本号与无共同组的 ClientHello：

   ```sh
   openssl s_client -connect 127.0.0.1:8080 -tls1_2 -brief </dev/null
   python3 tools/tls_abnormal_hello.py --addr localhost:8080 --mode bad-version
   python3 tools/tls_abnormal_hello.py --addr localhost:8080 --mode no-common-group
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-7-abnormal.pcap" 数据包：过滤 `tls.alert_message`，应看到 `Alert (Level: Fatal, Description: Protocol Version)`（desc=70），无共同组时看到 `Handshake Failure`（desc=40）。

   ```sh
   tshark -r tls-1-7-abnormal.pcap -Y "tls.alert_message" -T fields -e tls.alert_message.level -e tls.alert_message.desc
   ```

### TLS-1-8　无效密钥交换组处理（HelloRetryRequest）

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-1-8-hrr.pcap port 8080
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519，启动 TLS 服务端：

   ```sh
   .build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519
   ```

3. 打开 Terminal 终端，输入以下指令，指定首选密钥交换算法为服务端不支持的 DummyKex、并保留 X25519，启动 TLS 客户端：

   ```sh
   .build/client -kex DummyKex,X25519 -ca .build/certs/server_root_cert1.pem
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-8-hrr.pcap" 数据包：应看到第 1 条 ServerHello 的 random 为 HelloRetryRequest 固定值（`cf21ad74…8339c`），第 2 条 ServerHello 选中 0x001d（X25519），随后握手正常完成。

   ```sh
   python3 tools/tls_hello_check.py tls-1-8-hrr.pcap
   ```

### TLS-1-9　证书有效性验证

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-1-9-cert.pcap port 8211 or port 8212 or port 8231
   ```

2. 打开 Terminal 终端，输入以下指令，分别用"过期证书""有效证书 + 无关 CA""有效证书 + 对应 CA"启动 TLS 服务端与客户端（端到端自测，客户端加 `-verify` 打开证书链校验）：

   ```sh
   .build/e2e -cert tls-hybrid/server/server_root_cert1.pem -key tls-hybrid/server/server_root_key1.pem -ca tls-hybrid/server/server_root_cert1.pem -verify -addr localhost:8211
   .build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/other.crt -verify -addr localhost:8212
   .build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -verify -addr localhost:8231
   ```

3. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-9-cert.pcap" 数据包：

   - 三条连接都能看到**明文**的 ClientHello 与 ServerHello；
   - 端口 8211（过期证书）、8212（无关 CA）：服务端随后发出加密的 Certificate 等记录，客户端校验失败，回一条 19 字节的**加密 Alert**（`bad_certificate`）后断开，整条连接没有任何 Application Data；
   - 端口 8231（有效证书）：握手完成后出现 Application Data 记录；

   ```sh
   tshark -r tls-1-9-cert.pcap -Y "tcp.port == 8211" -T fields -e ip.src -e tcp.srcport -e tls.record.content_type
   ```

4. 若已按 §0 步骤 4 导出密钥日志（`SSLKEYLOGFILE=.build/keys.log`），在 wireshark 里配置好 (Pre)-Master-Secret 后重新打开该数据包，即可看到**明文**的 `Certificate`、`Finished`，以及客户端返回的 `Alert (Level: Fatal, Description: Bad Certificate)`；对应客户端日志分别是 `x509: certificate has expired or is not yet valid`、`x509: certificate signed by unknown authority` 和 `🔐 证书校验通过（-verify）`。

### TLS-1-10　加密通信验证

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-1-10-appdata.pcap port 8231
   ```

2. 打开 Terminal 终端，输入以下指令，启动 TLS 服务端与客户端，客户端发送文本数据：

   ```sh
   .build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -msg "测试文本数据 test text 123" -addr localhost:8231
   ```

3. 打开 Terminal 终端，输入以下指令，改为发送二进制数据：

   ```sh
   .build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -msg-hex 00ff1020304050607080 -addr localhost:8231
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-10-appdata.pcap" 数据包：握手完成后应只看到 `Application Data`（内容为密文，抓包中看不到明文），而服务端日志能打印出与发送内容一致的原文；若按 §0 步骤 4 导出了密钥日志，wireshark 配置 (Pre)-Master-Secret 后可直接看到解密的 `测试文本数据 test text 123` 与二进制 `00ff1020304050607080`。

   ```sh
   tshark -r tls-1-10-appdata.pcap -Y "tls.record.content_type == 23" | head
   ```

---

## B.2 混合抗量子 TLS 协议性能测试

### TLS-2-1　SM2Kyber512Draft00 单连接建立耗时

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-2-1-sm2kyber512-perf.pcap port 8099
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 SM2Kyber512Draft00，启动压测服务端：

   ```sh
   .build/tlsbench -mode server -addr :8099 -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex SM2Kyber512Draft00
   ```

3. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 SM2Kyber512Draft00，启动压测客户端，重复建立 200 次连接：

   ```sh
   .build/tlsbench -mode client -addr localhost:8099 -kex SM2Kyber512Draft00 -n 200
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-2-1-sm2kyber512-perf.pcap" 数据包：可数出 200 组 ClientHello/ServerHello；客户端统计行给出成功率与平均、P50/P90/P95/P99 建连耗时（实测成功率 200/200、平均约 4.9ms）。

### TLS-2-2　X25519Kyber512Draft00 单连接建立耗时

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-2-2-kyber512-perf.pcap port 8099
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber512Draft00，启动压测服务端：

   ```sh
   .build/tlsbench -mode server -addr :8099 -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber512Draft00
   ```

3. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber512Draft00，启动压测客户端，重复建立 200 次连接：

   ```sh
   .build/tlsbench -mode client -addr localhost:8099 -kex X25519Kyber512Draft00 -n 200
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-2-2-kyber512-perf.pcap" 数据包：key_share 组均为 0xfe30；客户端统计行给出成功率 200/200 与建连耗时（实测平均约 2.0ms）。

### TLS-2-3　X25519Kyber1024Draft00 单连接建立耗时

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-2-3-kyber1024-perf.pcap port 8099
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动压测服务端：

   ```sh
   .build/tlsbench -mode server -addr :8099 -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber1024Draft00
   ```

3. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动压测客户端，重复建立 200 次连接：

   ```sh
   .build/tlsbench -mode client -addr localhost:8099 -kex X25519Kyber1024Draft00 -n 200
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-2-3-kyber1024-perf.pcap" 数据包：key_share 组均为 0xfe36；客户端统计行给出成功率 200/200 与建连耗时（实测平均约 2.0ms）。

### TLS-2-4　并发多个 TLS 连接建立耗时

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-2-4-concurrency.pcap port 8099
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动压测服务端：

   ```sh
   .build/tlsbench -mode server -addr :8099 -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber1024Draft00
   ```

3. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，以 50 并发发起 1000 次连接：

   ```sh
   .build/tlsbench -mode client -addr localhost:8099 -kex X25519Kyber1024Draft00 -c 50 -n 1000
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-2-4-concurrency.pcap" 数据包：可见大量并发 ClientHello；客户端统计行给出成功率 1000/1000、总耗时与连接速率（实测约 2594 连接/秒）及 P50/P90/P95/P99 分位耗时。

### TLS-2-5　服务器资源消耗

1. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动压测服务端并记下进程号：

   ```sh
   .build/tlsbench -mode server -addr :8099 -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber1024Draft00 & echo "服务端PID=$!"
   ```

2. 打开 Terminal 终端，输入以下指令，采样空载时的 CPU 与内存占用（把 `<PID>` 换成上一步输出的进程号）：

   ```sh
   pidstat -p <PID> 1 5
   grep VmRSS /proc/<PID>/status; grep Threads /proc/<PID>/status
   ```

3. 打开 Terminal 终端，输入以下指令，持续发起连接制造负载：

   ```sh
   for i in $(seq 1 150); do .build/tlsbench -mode client -addr localhost:8099 -kex X25519Kyber1024Draft00 -n 20 >/dev/null 2>&1; done
   ```

4. 负载进行中，打开 Terminal 终端，输入以下指令，再次采样通信阶段的 CPU、内存与线程数：

   ```sh
   pidstat -p <PID> 1 5
   grep VmRSS /proc/<PID>/status; grep VmHWM /proc/<PID>/status; grep Threads /proc/<PID>/status
   ps -o pid,pcpu,pmem,rss,vsz,etime -p <PID>
   ```

5. 使用 wireshark 无需抓包即可；在负载过程中另开终端用 `sudo tcpdump -i lo -nn -s0 -w tls-2-5-load.pcap port 8099` 抓 10 秒，可看到持续的双向 Application Data。测试结束后在前一步的终端按 ctrl+c 或用 `kill <PID>` 停止服务端（实测：空载 %CPU≈0、RSS≈6.8MB、线程 6；负载 %CPU≈82%、RSS≈12.6MB、VmHWM≈12.7MB、线程 12）。

---

## B.3 混合抗量子 TLS 协议兼容性测试

### TLS-3-1　协商结果事件记录验证

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-3-1-negotiatedkex.pcap port 8080
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber768Draft00，启动 TLS 服务端：

   ```sh
   .build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber768Draft00
   ```

3. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber768Draft00，启动 TLS 客户端（协商结果由 `CFEventTLS13NegotiatedKEX` 事件打印）：

   ```sh
   .build/client -kex X25519Kyber768Draft00 -ca .build/certs/server_root_cert1.pem
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-3-1-negotiatedkex.pcap" 数据包：ServerHello 选中组 0x6399（X25519Kyber768Draft00），与客户端打印的 `Used X25519Kyber768Draft00` 一致。

   ```sh
   python3 tools/tls_hello_check.py tls-3-1-negotiatedkex.pcap --expect X25519Kyber768Draft00
   ```

### TLS-3-2　TLS ExportKeyingMaterial 密钥材料导出验证

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-3-2-keyingmaterial.pcap port 8231
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动 TLS 服务端与客户端，双方用导出密钥收发数据：

   ```sh
   .build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -kex X25519Kyber1024Draft00 -addr localhost:8231
   ```

3. 打开 Terminal 终端，输入以下指令，指定发送自定义内容以复核：

   ```sh
   .build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -kex X25519Kyber1024Draft00 -msg "hello-keying-material" -addr localhost:8231
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-3-2-keyingmaterial.pcap" 数据包：导出的密钥材料不出现在报文中（仅由双方各自计算），报文里只有密文的 Application Data；两端日志显示收发内容一致。

   ```sh
   tshark -r tls-3-2-keyingmaterial.pcap -Y "tls.record.content_type == 23" | head
   ```

### TLS-3-3　X25519 传统密钥交换回退验证

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-3-3-fallback.pcap port 8080
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519（仅传统算法），启动 TLS 服务端：

   ```sh
   .build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519
   ```

3. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519，启动 TLS 客户端：

   ```sh
   .build/client -kex X25519 -ca .build/certs/server_root_cert1.pem
   ```

4. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-3-3-fallback.pcap" 数据包：key_share 组为 0x001d、长度 32（无抗量子分量），客户端日志出现 `Used X25519`。

   ```sh
   python3 tools/tls_hello_check.py tls-3-3-fallback.pcap --expect X25519
   ```

### TLS-3-4　Linux 平台编译与运行验证

1. 打开 Terminal 终端，输入以下指令，交叉编译（同平台编译）出 Linux 服务端与客户端：

   ```sh
   ( cd tls-hybrid/server && go build -o ../../dist/tls/server/linux_server . )
   ( cd tls-hybrid/client && go build -o ../../dist/tls/client/linux_client . )
   file dist/tls/server/linux_server dist/tls/client/linux_client
   ```

2. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-3-4-linux.pcap port 8080
   ```

3. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，用刚编译的产物启动 TLS 服务端：

   ```sh
   dist/tls/server/linux_server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber1024Draft00
   ```

4. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，用刚编译的产物启动 TLS 客户端：

   ```sh
   dist/tls/client/linux_client -kex X25519Kyber1024Draft00 -ca .build/certs/server_root_cert1.pem
   ```

5. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-3-4-linux.pcap" 数据包：完成 TLS 1.3 握手（key_share 组 0xfe36），客户端日志出现 `Used X25519Kyber1024Draft00 (256 比特量子安全等级)`。

### TLS-3-5　Windows 目标平台交叉编译验证

1. 打开 Terminal 终端，输入以下指令，交叉编译出 Windows 服务端：

   ```sh
   ( cd tls-hybrid/server && GOOS=windows GOARCH=amd64 go build -o ../../dist/tls/server/windows_server.exe . )
   ```

2. 打开 Terminal 终端，输入以下指令，交叉编译出 Windows 客户端：

   ```sh
   ( cd tls-hybrid/client && GOOS=windows GOARCH=amd64 go build -o ../../dist/tls/client/windows_client.exe . )
   ```

3. 打开 Terminal 终端，输入以下指令，查看产物文件类型（应为 PE32+ x86-64，即 Windows 可执行文件）：

   ```sh
   file dist/tls/server/windows_server.exe dist/tls/client/windows_client.exe
   ```

4. 本条为交叉编译验证，不产生抓包；如需在 Windows 上运行验证，把上述两个 `.exe` 与 `.build/certs/` 下的证书一起拷到 Windows 机器，按 TLS-1-1 的步骤 2、3 运行并抓包。

---

## 附：新增用例

### TLS-1-11　混合密钥拼接结构验证（依据 RFC 9954）

1. 输入以下指令，运行 tcpdump，监听抓包：

   ```sh
   sudo tcpdump -i lo -nn -s0 -w tls-1-11-hybrid.pcap port 8099
   ```

2. 打开 Terminal 终端，输入以下指令，指定密钥交换算法 X25519Kyber1024Draft00，启动 TLS 服务端与客户端：

   ```sh
   .build/e2e -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -ca .build/certs/server_root_cert1.pem -kex X25519Kyber1024Draft00 -addr localhost:8099
   ```

3. 按键 ctrl+c 停止抓包，使用 wireshark 查看获取的 "tls-1-11-hybrid.pcap" 数据包：ClientHello/ServerHello 的 key_share 均为 1600 字节，即 X25519 公钥（32 字节）后直接拼接 Kyber1024 公钥/密文（1568 字节），中间没有长度字段。

   ```sh
   python3 tools/tls_hello_check.py tls-1-11-hybrid.pcap --expect X25519Kyber1024Draft00
   ```

4. 其余混合组按步骤 1~3 重复，只改 `-kex` 与 `--expect` 的组名（HQC 组需把 `.build/e2e` 换成 `.build/e2e_hqc`，组名写 `X25519HQC-128` / `X25519HQC-256`），各组的 key_share 长度应依次为：

   | 密钥交换算法 | ClientHello key_share | ServerHello key_share |
   |---|---|---|
   | SM2Kyber512Draft00 | 865 | 897 |
   | X25519Kyber512Draft00 | 832 | 800 |
   | X25519Kyber768Draft00 | 1216 | 1120 |
   | X25519Kyber1024Draft00 | 1600 | 1600 |
   | X25519HQC-128（`.build/e2e_hqc`） | 2281 | 4465 |
   | X25519HQC-256（`.build/e2e_hqc`） | 7277 | 14453 |
