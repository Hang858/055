#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
init_case "TLS-3-4" "Linux平台编译与运行验证"
skip_step 1 "编译 Linux 服务端与客户端" "需源码（go build tls-hybrid/server、tls-hybrid/client）；交付包只含可执行程序，按约定暂停"
finish_case
