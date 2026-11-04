#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
init_case "TLS-1-9" "无效密钥交换组处理"
skip_step 1 "DummyKex 触发 HelloRetryRequest 的客户端" "需源码编译的 .build/client（交付包 probe 不支持 DummyKex）；已实测交付包对未知组返回 handshake_failure，未实现 HRR"
finish_case
