# 交付包内置 TLS 自测

只依赖本包内的 `bin/pqc-gateway`、`bin/pqc-gateway-hqc`、`config/`、`demo/`，以及包根目录 `tools/` 下的 Python 脚本；不需要源码、Go 或 liboqs。

## 运行

```sh
bash tests/run-tests.sh                 # 全部可执行用例
bash "tests/TLS-1-1 格类128比特抗量子算法混合密钥交换.sh"   # 单条
```

结果写入 `tests/results/run-<时间戳>/<用例标识>/`（commands.log、output.log、summary.txt、captures/、analysis/）。

## 前置

- Python 3（脚本只用标准库）、bash；
- 抓包：root 运行时用 `tcpdump`；无权限时脚本自动进入 `unshare -Urn` 命名空间并用 `tools/pcap_capture.py` 抓包；
- 端口：网关 8443、本地回环后端 9000（脚本内可改）；
- `pidstat`（TLS-2-5）可选，缺失时该步会失败，不影响其他用例。

## 覆盖范围（14 条）

TLS-1-1～1-8、TLS-1-10～1-12、TLS-2-5、TLS-2-7、TLS-3-1。

## 不在此包内（需源码或需补功能）

- TLS-1-9（DummyKex 客户端；且网关未实现 HRR）
- TLS-1-13（go_kemtls + cloudflare 源码）
- TLS-2-1～2-4（需 `tlsbench` 压测程序；probe 不支持重复/并发）
- TLS-3-2（需 ExportKeyingMaterial，probe 未暴露）
- TLS-3-3（网关不支持纯 X25519 组，功能缺口）
- TLS-3-4、TLS-3-5（编译类用例，必须有源码）
