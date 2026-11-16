# KEMTLS-lab：KEM-SIG / SIG-KEM 流程验证

按图 2（KEM-SIG）和图 3（SIG-KEM）实现的独立双消息握手，用来验证异构 KEM/SIG 认证的消息流、签名覆盖范围、密钥派生和签名算法矩阵。它不依赖 TLS 1.3 的 Certificate/CertificateVerify 顺序，因此不会被“KEM secret 来晚了”的问题卡住。

## 两种模式

| 模式 | 客户端（Initiator） | 服务端（Responder） | 客户端认证 | 服务端认证 |
|---|---|---|---|---|
| KEM-SIG | KEM 证书 | SIG 公钥 | 静态 KEM 公钥封装/解封装 | 签名算法签名 |
| SIG-KEM | SIG 公钥 | KEM 证书 | 签名算法签名 | 静态 KEM 公钥封装/解封装 |

KEM 侧仍使用现有 `pqcerts/end-entity.pem` 和 Kyber768 私钥；SIG 侧改为 `pqsig` 的原始公钥/私钥，这样签名算法不再写死为 Dilithium2。

## 签名算法矩阵

| 族 | 算法 |
|---|---|
| Dilithium | `Dilithium2`、`Dilithium3`、`Dilithium5` |
| SLH-DSA | `SLH-DSA-SHA2-128s/128f/192s/192f/256s/256f` |

每种算法都跑 KEM-SIG 和 SIG-KEM 两条正向，共 18 条；另加两条缺 KEM 私钥负例。

## 消息流

KEM-SIG：

1. 客户端生成临时 Kyber768 密钥对，发送 `pk_tilde`。
2. 服务端封装 `c_tilde = Encaps(pk_tilde)`，再对客户端 KEM 证书公钥封装 `c_I = Encaps(pk_I)`，对 `pk_tilde || c_tilde || c_I` 用当前 SIG 算法签名，返回 `c_tilde || c_I || σ`。
3. 客户端验证 σ，解封装 `c_tilde` 和 `c_I`，双方派生 K。
4. 双方交换 Finished 和加密回显，确认密钥一致。

SIG-KEM：

1. 客户端生成临时 Kyber768 密钥对，封装服务端 KEM 证书公钥得到 `c_R`，对 `pk_tilde || c_R` 用当前 SIG 算法签名，发送 `pk_tilde || c_R || σ`。
2. 服务端验证 σ，解封装 `c_R`，再对 `pk_tilde` 封装得到 `c_tilde`，返回 `c_tilde`。
3. 客户端解封装 `c_tilde`，双方派生 K。
4. 双方交换 Finished 和加密回显。

## 和图的差异

- 图里没有 Finished，密钥确认是隐含的；本实验增加了 Finished 和 AES-GCM 回显，便于明确验证双方密钥一致。
- 图 3 用 `G(sk_I, r)` 派生临时 KEM 密钥；本实验用随机临时密钥对，功能等价，尚未实现确定性派生。
- KEM 证书信任采用“预置 peer 证书路径”，没有做 CA 链验证；SIG 公钥采用预置 peer 公钥文件。生产环境必须校验证书链、SAN 和身份绑定。
- KDF 用带域分离标签的 SHA-256 拼接，对应图中的 `H(...)`；不是完整 TLS 1.3 HKDF 结构。

## 构建

需要 patched Go 1.25.1（带 `crypto/myx509`）、本地 CIRCL 模块缓存，以及 `pqsig` 模块：

```bash
export GOROOT=$PWD/.build/extracted/go_kemtls
export GOMODCACHE=$PWD/.build/gomodcache-sm2auth
export GOCACHE=$PWD/.build/gocache-kemtls-fix
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
cd kemtls-lab
$GOROOT/bin/go build -o ../.build/kemtls-lab .
cd ../pqsig
$GOROOT/bin/go build -o ../.build/pqkey ./cmd/pqkey
```

## 运行

在仓库根目录执行：

```bash
bash kemtls-lab/run-tests.sh
```

脚本会自动生成九种签名算法的测试密钥，然后跑：

- KEM-SIG 正向 × 9
- SIG-KEM 正向 × 9
- KEM-SIG 缺客户端 KEM 私钥，必须失败
- SIG-KEM 缺服务端 KEM 私钥，必须失败

本机结果：

```text
PASS: KEM-SIG Dilithium2
PASS: SIG-KEM Dilithium2
PASS: KEM-SIG Dilithium3
PASS: SIG-KEM Dilithium3
PASS: KEM-SIG Dilithium5
PASS: SIG-KEM Dilithium5
PASS: KEM-SIG SLH-DSA-SHA2-128s
PASS: SIG-KEM SLH-DSA-SHA2-128s
PASS: KEM-SIG SLH-DSA-SHA2-128f
PASS: SIG-KEM SLH-DSA-SHA2-128f
PASS: KEM-SIG SLH-DSA-SHA2-192s
PASS: SIG-KEM SLH-DSA-SHA2-192s
PASS: KEM-SIG SLH-DSA-SHA2-192f
PASS: SIG-KEM SLH-DSA-SHA2-192f
PASS: KEM-SIG SLH-DSA-SHA2-256s
PASS: SIG-KEM SLH-DSA-SHA2-256s
PASS: KEM-SIG SLH-DSA-SHA2-256f
PASS: SIG-KEM SLH-DSA-SHA2-256f
PASS: KEM-SIG missing client KEM key fails
PASS: SIG-KEM missing server KEM key fails

passed=20 failed=0
```

## 手工运行

先生成 SIG 密钥：

```bash
.build/pqkey -alg SLH-DSA-SHA2-128s -out /tmp/server-sig
.build/pqkey -alg SLH-DSA-SHA2-128s -out /tmp/client-sig
```

KEM-SIG：客户端 KEM，服务端 SIG。

```bash
BIN=.build/kemtls-lab
S=packaging/tls-source/kemtls/cloudflare_server/pqcerts
C=packaging/tls-source/kemtls/cloudflare_client/pqcerts

$BIN -server -mode kemsig -listen 127.0.0.1:9443 \
  -sig-alg SLH-DSA-SHA2-128s -sig-key /tmp/server-sig.priv \
  -peer-cert $C/end-entity.pem &
$BIN -mode kemsig -connect 127.0.0.1:9443 \
  -cert $C/end-entity.pem -kem-key $C/end-entity-pq-key-KEM.bin \
  -sig-alg SLH-DSA-SHA2-128s -peer-sig-pub /tmp/server-sig.pub
```

SIG-KEM：客户端 SIG，服务端 KEM。

```bash
$BIN -server -mode sigkem -listen 127.0.0.1:9444 \
  -cert $S/end-entity.pem -kem-key $S/end-entity-pq-key-KEM.bin \
  -sig-alg SLH-DSA-SHA2-128s -peer-sig-pub /tmp/client-sig.pub &
$BIN -mode sigkem -connect 127.0.0.1:9444 \
  -peer-cert $S/end-entity.pem \
  -sig-alg SLH-DSA-SHA2-128s -sig-key /tmp/client-sig.priv
```
