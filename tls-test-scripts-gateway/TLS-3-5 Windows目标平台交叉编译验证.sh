#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
init_case "TLS-3-5" "Windows目标平台交叉编译验证"
skip_step 1 "交叉编译 Windows 产物" "需源码（GOOS=windows go build）；交付包只含可执行程序，按约定暂停"
finish_case
