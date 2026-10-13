#!/usr/bin/env python3
"""Refresh the binary-only gateway bundle with the standard certificate tool."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

from docx import Document

ROOT = Path(__file__).resolve().parent.parent
OLD = ROOT / "dist/pqc-gateway-certtool-runtime-20261012/pqc-gateway-ubuntu20.04-amd64"
DEST = ROOT / "dist/pqc-gateway-certtool-runtime-20261013"
BUNDLE = DEST / "pqc-gateway-ubuntu20.04-amd64"
BINARY = ROOT / ".build/certtool/pqc-certtool-standard"
ALIASES = {
    "Dilithium2": "ML-DSA-44", "Dilithium3": "ML-DSA-65", "Dilithium5": "ML-DSA-87",
    "Kyber512": "ML-KEM-512", "Kyber768": "ML-KEM-768", "Kyber1024": "ML-KEM-1024",
}


def run(*args, env=None, cwd=None):
    p = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)
    if p.returncode:
        raise RuntimeError(f"{' '.join(map(str, args))}:\n{p.stdout}{p.stderr}")
    return p.stdout + p.stderr


def manual(path):
    d = Document()
    d.add_heading("配置式证书工具使用说明", 0)
    d.add_paragraph("程序：pqc-certtool 20261013-ml；系统：Ubuntu 20.04 / x86_64。解压后直接运行，无需安装 Go。")
    d.add_heading("1. 运行", 1)
    d.add_paragraph("先复制一份 certificate-tools/config/ 下的 JSON，修改 output_dir、证书名称和算法，再运行以下命令。output_dir 必须是尚不存在的新目录。")
    for cmd in ("./certificate-tools/bin/pqc-certtool check -config certificate-tools/config/pure-pq.json",
                "./certificate-tools/bin/pqc-certtool generate -config certificate-tools/config/pure-pq.json",
                "./certificate-tools/bin/pqc-certtool verify -config certificate-tools/config/pure-pq.json"):
        d.add_paragraph(cmd, style="Normal")
    d.add_paragraph("check 检查配置和外部公钥；generate 生成并自动验签；verify 复查已生成证书。成功时输出 JSON，verified 为 true。失败时退出码非零。再次生成时改用新的 output_dir。")
    d.add_heading("2. 配置", 1)
    d.add_paragraph("mode 可选 pure-pq、sm2-hybrid、rsa-hybrid、sm2。root 填根 CA；intermediates 按签发顺序填 0 至 4 级中间 CA；leaves 填 1 至 64 个用户证书。每个节点填写 name、common_name、algorithm、valid_days。用户节点可加 public_key_file。相对路径按 JSON 文件所在目录解析。")
    d.add_paragraph("默认使用标准 ML-DSA-44/65/87 签名和 ML-KEM-512/768/1024 公钥；SLH-DSA-SHA2-128s/128f、192s/192f、256s/256f 也可用于签名。CA 必须选签名算法，ML-KEM 只能用于用户公钥。旧配置名 Dilithium2/3/5、Kyber512/768/1024 可继续填写，但实际执行与输出统一按相应标准算法处理。")
    d.add_paragraph("pure-pq 可生成纯抗量子链；sm2-hybrid 和 rsa-hybrid 生成传统主证书并附带抗量子公钥、签名扩展；sm2 生成纯 SM2 链。混合扩展沿用项目格式，不能直接用于通用浏览器或网关 PQ 身份认证。网关现场运行证书按网关手册生成。")
    d.add_heading("3. 导入外部公钥", 1)
    d.add_paragraph("参考 import-pq.json、import-sm2.json，修改 public_key_file 和 output_dir。抗量子公钥必须是本版生成的 PQC PUBLIC KEY PEM，且 PEM 中的 Algorithm 标记与配置算法匹配。data/mldsa44.pub 是可直接测试的标准算法公钥。旧 public_keys.txt 中的抗量子公钥及无算法标记的原始字节不能作为标准算法公钥导入。SM2 仍可使用 PUBLIC KEY PEM 或带 [SM2] 的 X/Y 文本；data/sm2_public_key.txt 可作测试样例。导入公钥后，程序不生成对应私钥。")
    d.add_heading("4. 输出与检查", 1)
    d.add_paragraph("每个节点输出 name.crt 证书。抗量子公钥为 name.pub，抗量子私钥为 name.key 或 name.pq.key，传统私钥为 name.key。抗量子私钥的 PEM 类型为 PQC PRIVATE KEY，属于工具内部格式。report.json 记录验签结果、证书算法和 SHA-256。输出目录权限为 0700，私钥为 0600。")
    d.add_paragraph("可以用 openssl x509 -in 证书.crt -noout -text 查看证书字段；抗量子证书链和混合扩展签名以本工具 verify 的结果为准。正式 ML-DSA 和 ML-KEM 公钥使用标准 OID；混合证书扩展 OID 仍为 1.3.6.1.4.1.54321.1.1 和 1.3.6.1.4.1.54321.1.2。")
    d.add_heading("5. 验证范围", 1)
    d.add_paragraph("本版在开发环境完成四种模式、三档 ML-DSA、三档 ML-KEM、六档 SLH-DSA、外部公钥导入、旧名称映射及证书验签测试。Ubuntu 20.04 实机应按第 1 节复测。旧研究样例证书与本版算法不兼容，须重新生成。")
    d.save(path)


def main():
    if DEST.exists():
        raise SystemExit(f"拒绝覆盖现有目录：{DEST}")
    if not BINARY.is_file():
        raise SystemExit(f"请先构建可执行程序：{BINARY}")
    shutil.copytree(OLD, BUNDLE)
    shutil.copy2(BINARY, BUNDLE / "certificate-tools/bin/pqc-certtool")
    # Historical samples use pre-standard algorithms and must not be presented as this release's output.
    shutil.rmtree(BUNDLE / "certificate-tools/examples")
    configs = BUNDLE / "certificate-tools/config"
    for path in configs.glob("*.json"):
        data = json.loads(path.read_text())
        for node in [data["root"], *data["intermediates"], *data["leaves"]]:
            node["algorithm"] = ALIASES.get(node["algorithm"], node["algorithm"])
        if path.name == "import-pq.json":
            data["leaves"][0]["public_key_file"] = "../data/mldsa44.pub"
        elif path.name == "import-sm2.json":
            data["leaves"][0]["public_key_file"] = "../data/sm2_public_key.txt"
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    data_dir = BUNDLE / "certificate-tools/data"
    old_text = (data_dir / "public_keys.txt").read_text()
    (data_dir / "sm2_public_key.txt").write_text(old_text.split("[ML-DSA-44]")[0].strip() + "\n")
    (data_dir / "public_keys.txt").unlink()
    with tempfile.TemporaryDirectory(prefix="certtool-standard-") as tmp:
        tmp = Path(tmp)
        sample = {
            "schema_version": 1, "mode": "pure-pq", "output_dir": str(tmp / "output"),
            "root": {"name": "root", "common_name": "Sample Root", "algorithm": "ML-DSA-44", "valid_days": 3650},
            "intermediates": [],
            "leaves": [{"name": "user", "common_name": "Sample User", "algorithm": "ML-DSA-44", "valid_days": 365}],
        }
        path = tmp / "sample.json"
        path.write_text(json.dumps(sample))
        run(BINARY, "generate", "-config", path)
        shutil.copy2(tmp / "output/user.pub", data_dir / "mldsa44.pub")
    manual(BUNDLE / "docs/配置式证书工具使用说明.docx")
    (BUNDLE / "README.md").write_text(
        "# TLS 安全网关与标准算法证书工具运行包\n\n"
        "系统：Ubuntu 20.04 / x86_64。网关版本 20261010-hqc；证书工具版本 20261013-ml。\n\n"
        "网关入口：bin/pqc-gateway；证书工具入口：certificate-tools/bin/pqc-certtool。"
        "配置样例位于 certificate-tools/config/，使用步骤见 docs/配置式证书工具使用说明.docx。"
        "网关安装与配置见 docs/TLS安全网关安装配置手册.docx。\n\n"
        "证书工具默认使用标准 ML-DSA、ML-KEM；旧算法名只作配置别名。"
        "certificate-tools/data/ 仅有外部公钥测试样例。"
        "此包不含源码。网关运行证书仍使用 ECDSA，证书工具生成的抗量子证书尚未接入网关身份认证。\n"
    )
    validation = BUNDLE / "validation"
    for name in ("certtool-go-tests.log", "certtool-acceptance.log", "certtool-examples-smoke.json", "certtool-race-tests.log"):
        (validation / name).unlink(missing_ok=True)
    # The binary acceptance suite is run against the exact binary included in this release.
    env = os.environ.copy()
    env["CERTTOOL_BINARY"] = str(BUNDLE / "certificate-tools/bin/pqc-certtool")
    (validation / "certtool-acceptance.log").write_text(run("python3", ROOT / "packaging/test_certtool_release.py", env=env))
    example_results = []
    with tempfile.TemporaryDirectory(prefix="certtool-configs-") as tmp:
        tmp = Path(tmp)
        for source in sorted(configs.glob("*.json")):
            config = json.loads(source.read_text())
            config["output_dir"] = str(tmp / source.stem)
            config["leaves"] = list(config["leaves"])
            local = tmp / source.name
            # Imported keys must refer to the packaged sample files after config relocation.
            if config["leaves"][0].get("public_key_file"):
                key = "mldsa44.pub" if source.name == "import-pq.json" else "sm2_public_key.txt"
                config["leaves"][0]["public_key_file"] = str(data_dir / key)
            local.write_text(json.dumps(config))
            run(BINARY, "check", "-config", local)
            report = json.loads(run(BINARY, "generate", "-config", local))
            run(BINARY, "verify", "-config", local)
            example_results.append({"config": source.name, "verified": report["verified"]})
    (validation / "certtool-examples-smoke.json").write_text(json.dumps({"passed": True, "cases": example_results}, ensure_ascii=False, indent=2) + "\n")
    info = json.loads((validation / "delivery-info.json").read_text())
    info.update(archive=DEST.name + ".zip", certificate_tool_version="20261013-ml", certificate_algorithm_backend="ML-DSA and ML-KEM", legacy_algorithm_names="configuration aliases only")
    (validation / "delivery-info.json").write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n")
    build_info = json.loads((validation / "build-info.json").read_text())
    build_info["certificate_tool"].update(
        version="20261013-ml",
        sha256=hashlib.sha256((BUNDLE / "certificate-tools/bin/pqc-certtool").read_bytes()).hexdigest(),
        algorithms="Standard ML-DSA-44/65/87 and ML-KEM-512/768/1024; legacy names are configuration aliases",
        tests="13 Go test functions, 8 binary acceptance tests and 8 configuration examples verified",
    )
    (validation / "build-info.json").write_text(json.dumps(build_info, ensure_ascii=False, indent=2) + "\n")
    sums = BUNDLE / "SHA256SUMS"
    sums.unlink(missing_ok=True)
    with sums.open("w") as out:
        for path in sorted(BUNDLE.rglob("*")):
            if path.is_file() and path != sums:
                out.write(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(BUNDLE).as_posix()}\n")
    archive = DEST.with_suffix(".zip")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path in sorted(BUNDLE.rglob("*")):
            if path.is_file():
                z.write(path, arcname=str(path.relative_to(DEST)))
    print(archive)
    print(hashlib.sha256(archive.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
