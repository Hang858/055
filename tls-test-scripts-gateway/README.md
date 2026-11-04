# TLS 测试脚本（交付运行包版）

服务端使用**交付运行包** `dist/pqc-gateway-hybrid-mlkem-ubuntu20.04-amd64-20261013.zip` 中的 `bin/pqc-gateway`（HQC 用 `bin/pqc-gateway-hqc`），客户端使用同一程序的 `probe` 子命令，不依赖任何源码编译产物。

## 用法

```sh
bash tls-test-scripts-gateway/run_all.sh          # 全量
bash "tls-test-scripts-gateway/TLS-1-1 格类128比特抗量子算法混合密钥交换.sh"
```

- 结果：`tls-test-scripts-gateway/results/run-<时间戳>/<用例标识>/`（commands.log、output.log、summary.txt、captures/、analysis/）
- 交付包缺失时自动解压到 `.build/delivery/`；证书取包内 `demo/44`、`demo/87`
- 服务端启动：`bin/pqc-gateway serve -config <用例配置>`；客户端：`bin/pqc-gateway probe ... -kex <组>`
- 与源码版脚本（`tls-test-scripts/`）的区别：KEX 通过 JSON 配置注入；性能类 `tlsbench` 用例无法用 `probe` 替代（probe 单次一个连接）

## 结果判定口径

- PASS：交付包可执行并通过断言
- FAIL：交付包功能缺陷（如 TLS-3-3：不支持纯 X25519 组）
- SKIP：需要源码程序才能运行（`.build/client` 的 DummyKex、`.build/tlsbench`、`.build/e2e` 密钥导出、`go build`、`go_kemtls`），按约定暂停，不计入通过/失败

详细结果见 `测试结果-交付运行包.md`。
