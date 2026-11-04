#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
init_case "TLS-3-2" "TLS ExportKeyingMaterial密钥材料导出验证"
skip_step 1 "导出密钥材料并核对" "需源码 .build/e2e 的 ExportKeyingMaterial 能力（交付包 probe 不暴露密钥材料），按约定暂停"
finish_case
