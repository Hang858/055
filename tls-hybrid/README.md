# 编译与运行（路径均为项目内相对路径，命令在**项目根目录**执行）

服务端第一次运行前需编译**打过补丁的** Go 1.22.12（见 [`docs/BUILD.md`](../docs/BUILD.md) A 节）：

```sh
# 端到端自测（单进程同时起服务端 + 客户端）
( cd tls-hybrid/e2e && go build -o ../../.build/e2e . )

# 独立服务端 / 客户端
( cd tls-hybrid/server && go build -o ../../.build/server . )
( cd tls-hybrid/client && go build -o ../../.build/client . )

# 交叉编译（TLS-3-4 / TLS-3-5 用）
( cd tls-hybrid/server && GOOS=linux   GOARCH=amd64 go build -o ../../dist/tls/server/linux_server . )
( cd tls-hybrid/server && GOOS=windows GOARCH=amd64 go build -o ../../dist/tls/server/windows_server.exe . )
( cd tls-hybrid/client && GOOS=linux   GOARCH=amd64 go build -o ../../dist/tls/client/linux_client . )
( cd tls-hybrid/client && GOOS=windows GOARCH=amd64 go build -o ../../dist/tls/client/windows_client.exe . )
```

运行示例（证书由 `docs/测试大纲-输入及操作-细化.md` §0.3 生成到 `.build/certs/`）：

```sh
.build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex SM2Kyber512Draft00
.build/client -kex SM2Kyber512Draft00 -ca .build/certs/server_root_cert1.pem
```

完整的逐条测试命令见 [`docs/测试大纲-输入及操作-细化.md`](../docs/测试大纲-输入及操作-细化.md)。
