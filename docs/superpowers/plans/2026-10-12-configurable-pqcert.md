# Configurable PQ certificate tool implementation plan

> For agentic workers: use superpowers:executing-plans inline.

Goal: one offline executable using JSON to generate and verify existing certificate families.
Architecture: separate strict configuration, crypto registry/key import, ASN.1 generation, chain verification and CLI modules under pqcert/configurable; existing tools stay intact.
Tech stack: Go1.25.1, cached CIRCL1.6.3 and gmsm1.4.1, CGO_ENABLED=0.
Spec: docs/superpowers/specs/2026-10-12-configurable-pqcert-design.md

Global constraints: no source in delivered archive, no overwrite, private keys0600, relative paths based on config, legacy algorithms accurately named, no gateway auth changes.
Review focus: unknown fields/trailing JSON; path traversal/symlink output; malformed imported keys; hybrid signatures tampered independently; issuer/validity/CA constraints and config mismatch.

1. Write executable-level tests for config failures, all certificate modes, chain customization, algorithm coverage, import, no-overwrite, permissions and tampering. Run to establish missing executable failure.
2. Implement config.go and algorithms.go with exact validation and leaf-only public key import; implement certificate.go, generate.go and verify.go using existing libraries and strict full-chain checks; main.go returns nonzero on any failure.
3. Run whole new-module suite and executable-level tests; fix identified faults, then review independently via requesting-code-review.
4. Build static executable, create five config examples and Word manual. Update gateway runtime manual and launcher to unified program; package without legacy executable duplication or source, preserving old research samples explicitly.
5. Run packaged executable acceptance, archive CRC/SHA and extracted file/permission checks. Report actual target-host limitation and tested commands.

完成记录：全部五项完成。修复原始二进制导入、SM2越界坐标、主体曲线及ASCII/Unicode JSON别名问题，均留有先失败后通过的记录。独立审查无剩余Important。全模块、黑盒、race、vet、24示例命令及28网关验收通过，压缩包pqc-gateway-certtool-runtime-20261012.zip完整性和解压运行通过。没有执行提交、合并或发布。
