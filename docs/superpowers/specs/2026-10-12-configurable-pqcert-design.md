# 配置式证书工具设计

目的：把现有证书生成能力整理成一个 Linux x86_64 可执行程序，厂内人员只改 JSON 配置，不需要源码或编译工具链。

接口：pqc-certtool version / algorithms / check -config PATH / generate -config PATH / verify -config PATH。
JSON schema_version=1，mode 为 pure-pq、sm2-hybrid、rsa-hybrid 或 sm2；output_dir 相对配置文件解析。root、intermediates、leaves 中指定 name（安全文件名）、common_name、algorithm、valid_days。叶证书可设置 public_key_file（原始公钥 PEM/二进制或原项目 public_keys.txt）。每级有效期不得超过签发者，CA 必须用签名算法，KEM 只用于叶证书。

复用 CIRCL 1.6.3 的 Dilithium2/3/5、SLH-DSA-SHA2 六种参数及 Kyber512/768/1024；SM2 复用 gmsm 1.4.1。算法名称明确区分旧 Dilithium 与 ML-DSA。纯 PQ 采用标准 X.509 ASN.1 外形及项目私有算法 OID；混合模式使用传统 RSA/SM2 主签名和带算法信息的 PQ 扩展。不会声称与原研究证书格式或网关 PQ 身份认证兼容。

生成全部证书、可导出的私钥及公钥，私钥权限 0600，输出目录 0700。输出目录必须不存在，失败清理本次临时目录，绝不覆盖已有证书。全部证书自动完成签名、签发关系、有效期和 CA 约束检查后才发布结果。混合验签同时验证传统签名和 PQ 扩展；verify 不使用私钥，只按指定配置检查生成的链，不能代替独立信任根管理。

不增加 CA 服务、CSR、续签、吊销、浏览器或网关认证改造。交付仍为 Ubuntu20.04/x86_64 目标，当前环境验证；附静态程序、四类配置及外部公钥示例、简明 Word 手册、测试记录和校验值。保留原交付包，生成新的网关与证书工具合并运行包。
