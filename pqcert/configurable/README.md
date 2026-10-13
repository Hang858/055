# 配置式证书工具

pqc-certtool通过JSON生成并验证pure-pq、sm2-hybrid、rsa-hybrid及sm2证书链。旧五个工具保留在原目录，统一程序位于本目录。

交付程序和配置见dist/pqc-gateway-certtool-runtime-20261012.zip；用户步骤见包内docs/配置式证书工具使用说明.docx。证书工具尚未接入网关PQC身份认证。

开发构建：Go1.25.1，CGO_ENABLED=0，go build -trimpath -ldflags="-s -w" -o pqc-certtool .。运行go test ./...及go vet ./...；可执行程序验收使用CERTTOOL_BINARY指向构建结果，再运行packaging/test_certtool_release.py。

默认签名算法为标准ML-DSA-44/65/87，KEM为标准ML-KEM-512/768/1024。旧配置名Dilithium2/3/5、Kyber512/768/1024仍可填写，但实际使用标准算法，报告和新证书都标明标准名称。SLH-DSA继续支持。ML-DSA与ML-KEM证书字段使用标准OID；混合证书的抗量子扩展仍为项目私有格式，不承诺通用浏览器或网关身份认证兼容。

外部抗量子公钥须为本版输出的PQC PUBLIC KEY PEM，且带有Algorithm头。旧public_keys.txt中的PQ段和无算法标记的原始公钥字节不能导入；旧密钥与新算法不能直接互用。SM2外部公钥格式保持不变。每次generate生成全新CA及证书，只发布验签成功的结果，拒绝覆盖已有目录。
