# 证书工具使用说明

## 运行测试用例

在压缩包解压后的根目录执行全部用例：

```bash
bash run-certtool-test-pipeline.sh
```

单独运行一条用例，例如：

```bash
bash 'certtool-test-scripts/ZS-1-19 私钥 PEM 文件输出测试.sh'
```

每条脚本都会准备独立配置，执行配置检查、证书生成和证书链验证，再检查该用例的输出。运行结果保存在 `results/`；pipeline 另生成 `summary.tsv` 和逐项日志。运行环境需要 Bash、Python 3 和 OpenSSL。测试结果包含私钥，使用后按厂内密钥管理要求处理。文件名中的全角 `／` 表示用例名称中的 `/`。

## 作为证书工具使用

`bin/pqc-certtool` 是证书工具可执行程序。先复制 `config/` 中接近需求的 JSON 样例，修改 `output_dir`、证书名称、算法和有效期，再依次执行：

```bash
cp config/pure-pq.json my-cert-config.json
# 编辑 my-cert-config.json
bin/pqc-certtool check -config my-cert-config.json
bin/pqc-certtool generate -config my-cert-config.json
bin/pqc-certtool verify -config my-cert-config.json
```

`output_dir` 是输出目录，建议每次生成使用新的目录；相对路径以配置文件所在目录为基准。`mode` 可选 `pure-pq`、`rsa-hybrid`、`sm2-hybrid`、`sm2`。SLH-DSA 使用 `pure-pq` 模式，样例见 `config/slh-dsa.json`。`root`、`intermediates`、`leaves` 分别配置根证书、中间证书和终端证书；每项的 `name` 是输出文件名，`common_name` 是证书主题名，`algorithm` 是算法，`valid_days` 是有效天数。用 `bin/pqc-certtool algorithms` 查看当前程序支持的算法。若需导入外部公钥，参考 `config/import-pq.json`、`config/import-sm2.json` 和 `data/` 中的样例。更多字段说明见 `docs/配置式证书工具使用说明.docx`。
