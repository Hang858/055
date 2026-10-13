#!/usr/bin/env python3
"""Package the binary-only certificate tool and its per-case acceptance scripts."""
import hashlib
from pathlib import Path
import shutil
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "dist/pqc-gateway-certtool-runtime-20261013/pqc-gateway-ubuntu20.04-amd64"
DEST = ROOT / "dist/pqc-certtool-test-suite-20261013-v2"
BUNDLE = DEST / "pqc-certtool-test-suite-ubuntu20.04-amd64"
LOCAL_RESULTS = ROOT / ".build/certtool-case-results-20261013-21"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if DEST.exists():
        raise SystemExit(f"拒绝覆盖交付目录：{DEST}")
    for directory in (BUNDLE / "bin", BUNDLE / "config", BUNDLE / "data", BUNDLE / "docs", BUNDLE / "validation"):
        directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE / "certificate-tools/bin/pqc-certtool", BUNDLE / "bin/pqc-certtool")
    shutil.copytree(SOURCE / "certificate-tools/config", BUNDLE / "config", dirs_exist_ok=True)
    shutil.copytree(SOURCE / "certificate-tools/data", BUNDLE / "data", dirs_exist_ok=True)
    shutil.copytree(ROOT / "certtool-test-scripts", BUNDLE / "certtool-test-scripts")
    shutil.copy2(ROOT / "run-certtool-test-pipeline.sh", BUNDLE / "run-certtool-test-pipeline.sh")
    shutil.copy2(SOURCE / "docs/配置式证书工具使用说明.docx", BUNDLE / "docs/配置式证书工具使用说明.docx")
    shutil.copy2(ROOT / "抗量子证书生成工具测试大纲.docx", BUNDLE / "docs/抗量子证书生成工具测试大纲.docx")
    shutil.copy2(LOCAL_RESULTS / "summary.tsv", BUNDLE / "validation/local-pipeline-summary.tsv")
    shutil.copy2(LOCAL_RESULTS / "ZS-2-2/summary.txt", BUNDLE / "validation/local-performance-summary.txt")
    shutil.copytree(LOCAL_RESULTS / "logs", BUNDLE / "validation/logs")
    expected = list((BUNDLE / "certtool-test-scripts").glob("ZS-*.sh"))
    if len(expected) != 21 or len((BUNDLE / "validation/local-pipeline-summary.tsv").read_text().splitlines()) != 21:
        raise SystemExit("用例脚本或本地结果不是 21 条")
    shutil.copy2(ROOT / "certtool-test-scripts/README.md", BUNDLE / "README.md")
    sums = BUNDLE / "SHA256SUMS"
    sums.write_text("".join(f"{digest(path)}  {path.relative_to(BUNDLE).as_posix()}\n"
                            for path in sorted(BUNDLE.rglob("*")) if path.is_file() and path != sums))
    archive = DEST.with_suffix(".zip")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for path in sorted(BUNDLE.rglob("*")):
            if path.is_file():
                output.write(path, arcname=str(path.relative_to(DEST)))
    print(archive)
    print(digest(archive))


if __name__ == "__main__":
    main()
