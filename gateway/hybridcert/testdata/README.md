# 测试证书

`44`、`87`及`intermediate44`目录中的证书和私钥只供自动化测试使用，不能安装到生产网关。它们由`pqcert/configurable`的`sm2-hybrid`模式生成。`44`、`87`分别对应`examples/tls-sm2-mldsa44.json`、`examples/tls-sm2-mldsa87.json`；`intermediate44`在44样例的`intermediates`中增加了名为`ca`的ML-DSA-44中间CA。
