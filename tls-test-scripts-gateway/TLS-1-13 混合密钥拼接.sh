#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
init_case "TLS-1-13" "混合密钥拼接（异构 Sig/KEM 认证）"
skip_step 1 "异构 Sig/KEM 认证（四模式）" "需源码：go_kemtls 工具链 + cloudflare_server/client（交付包只含 pqc-gateway 可执行程序），按约定暂停"
finish_case
