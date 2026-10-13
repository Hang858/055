# 配置式证书工具

pqc-certtool通过JSON生成并验证pure-pq、sm2-hybrid、rsa-hybrid及sm2证书链。旧五个工具保留在原目录，统一程序位于本目录。

旧版交付程序和配置见dist/pqc-gateway-certtool-runtime-20261012.zip；用户步骤见包内docs/配置式证书工具使用说明.docx。本目录新增的TLS证书字段尚未重新打入该交付包。

TLS双签身份样例见`examples/tls-sm2-mldsa44.json`和`examples/tls-sm2-mldsa87.json`。复制样例后修改`output_dir`、名称及有效期，再运行`pqc-certtool check -config 配置.json`、`pqc-certtool generate -config 配置.json`、`pqc-certtool verify -config 配置.json`。`output_dir`须指向尚不存在的目录，相对路径以配置文件所在目录为基准。

`sm2-hybrid`模式的叶子证书可设置`tls_usage`为`server`或`client`。服务端须同时设置至少一个`dns_names`或`ip_addresses`，其值必须与客户端连接时使用的域名或IP一致。生成结果中的`root.crt`是信任根，`server.crt`、`server.key`和`server.pq.key`分别是服务端证书、SM2私钥和ML-DSA私钥；客户端对应使用`client`前缀。每一级中间CA均由`intermediates`配置生成，并需按根到叶顺序交给网关证书适配层。私钥只放在对应设备，根私钥不得放到网关。

网关现已能独立校验这类证书的SM2和ML-DSA证书签名、证书链、用途、有效期、SAN和两份私钥是否匹配；TLS握手中的双签身份认证仍在后续阶段实现。

开发构建：Go1.25.1，CGO_ENABLED=0，go build -trimpath -ldflags="-s -w" -o pqc-certtool .。运行go test ./...及go vet ./...；可执行程序验收使用CERTTOOL_BINARY指向构建结果，再运行packaging/test_certtool_release.py。

默认签名算法为标准ML-DSA-44/65/87，KEM为标准ML-KEM-512/768/1024。旧配置名Dilithium2/3/5、Kyber512/768/1024仍可填写，但实际使用标准算法，报告和新证书都标明标准名称。SLH-DSA继续支持。ML-DSA与ML-KEM证书字段使用标准OID；混合证书的抗量子扩展仍为项目私有格式，不承诺通用浏览器或网关身份认证兼容。

外部抗量子公钥须为本版输出的PQC PUBLIC KEY PEM，且带有Algorithm头。旧public_keys.txt中的PQ段和无算法标记的原始公钥字节不能导入；旧密钥与新算法不能直接互用。SM2外部公钥格式保持不变。每次generate生成全新CA及证书，只发布验签成功的结果，拒绝覆盖已有目录。
