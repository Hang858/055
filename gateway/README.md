# TLS 安全网关：SM2 + ML-DSA 服务端认证

本阶段支持 TLS 1.3 服务端双签身份认证。`sm2-mldsa-44`使用 SM2 与标准 ML-DSA-44；`sm2-mldsa-87`使用 SM2 与标准 ML-DSA-87。客户端在`signature_algorithms`中声明项目私有码点`0xfea0`或`0xfea1`。网关发送同一份 TLS `CertificateVerify` 输入上的两份签名；客户端逐级验证证书链的 SM2 和 ML-DSA 签名，并同时验证握手双签。任一验证失败即终止连接。

## 准备证书

用`pqcert/configurable/examples/tls-sm2-mldsa44.json`或`tls-sm2-mldsa87.json`生成证书。修改`output_dir`和`server`叶子证书的`dns_names`或`ip_addresses`，然后运行：

```sh
pqc-certtool check -config tls-certs.json
pqc-certtool generate -config tls-certs.json
pqc-certtool verify -config tls-certs.json
```

把`server.crt`、`server.key`、`server.pq.key`和`root.crt`放到网关指定目录。客户端只需要`root.crt`。如果使用中间 CA，网关配置中的`intermediates`须按根到叶顺序填写中间证书；网关发给客户端时会改为 TLS 要求的叶到根顺序。私钥只放在网关，不要复制到客户端。

## 配置和运行

参考`examples/hybrid-44.json`或`examples/hybrid-87.json`修改`listen`、`upstream`、证书路径和`server_name`。证书路径相对配置文件所在目录解析。`server_name`必须出现在服务端证书的 SAN 中。`auth`和`kex`分别配置身份认证与密钥交换；128 档样例使用 SM2Kyber512Draft00，256 档样例使用 SM2Kyber1024Draft00。

```sh
pqc-gateway check -config gateway-hybrid.json
pqc-gateway serve -config gateway-hybrid.json
```

在客户端使用同一补丁工具链构建的`pqc-gateway`程序执行：

```sh
pqc-gateway probe -url https://gateway.factory.local:8443/ -ca root.crt -auth sm2-mldsa-44 -kex SM2Kyber512Draft00
```

访问地址是 IP 时，加`-server-name gateway.factory.local`；若证书只含 IP SAN，可把该参数设为证书中的 IP。probe 成功后输出实际协商的密钥交换组，并报告已验证的签名档位。使用 256 档时把`-auth`改成`sm2-mldsa-87`，`-kex`改成`SM2Kyber1024Draft00`。

在混合认证配置中填写`client_ca`会要求客户端提供同档位的 SM2+ML-DSA 双签证书。probe 加`-cert`、`-key`、`-pq-key`；客户端证书由另一根 CA 签发时加`-client-ca`。缺少客户端证书或任一签名验证失败，网关拒绝连接。

传统 ECDSA 配置仍可使用：不设置`auth`或设为`ecdsa`，并使用原有`cert`、`key`和`client_ca`字段。传统兼容服务可运行在独立端口；混合认证端口不回退到传统认证。混合认证禁用 TLS 会话票据，避免恢复会话绕过证书与双签检查。

网关及 probe 均须使用依次应用`patches/go1.22.12-sm2-mldsa-auth.patch`和`patches/go1.22.12-sm2-mldsa-mtls.patch`的 Go 1.22.12 工具链编译。构建步骤见[补丁说明](../patches/README.md)。项目私有码点及 SM2 混合证书扩展不是通用浏览器格式。二进制运行包位于`dist/pqc-gateway-hybrid-ubuntu20.04-amd64-20261013.zip`，不含应用源码。
