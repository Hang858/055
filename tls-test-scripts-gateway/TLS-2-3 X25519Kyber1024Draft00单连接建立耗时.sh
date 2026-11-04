#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
init_case "TLS-2-3" "X25519Kyber1024Draft00单连接建立耗时"
skip_step 1 "执行性能用例" "需源码编译的 .build/tlsbench（交付包 probe 不支持 -n 重复与 -c 并发），按约定暂停"
finish_case
