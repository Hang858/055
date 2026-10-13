#!/usr/bin/env python3
"""Build and validate a binary-only Ubuntu 20.04 / amd64 hybrid gateway ZIP."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parent.parent
NAME = "pqc-gateway-hybrid-mlkem-ubuntu20.04-amd64-20261013"
TLS_ROOT = ROOT / ".build/go"
PQ_ROOT = ROOT / ".build/gopath/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.1.linux-amd64"


def run(args, cwd=None, env=None, output=None):
    result = subprocess.run(list(map(str, args)), cwd=cwd, env=env, capture_output=True,
                            text=True, timeout=180)
    if output is not None:
        output.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError("command failed: " + " ".join(map(str, args)) + "\n" +
                           result.stdout + result.stderr)
    return result.stdout


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def tls_env(hqc=False):
    env = os.environ.copy()
    env.update(GOROOT=str(TLS_ROOT), GOMODCACHE=str(ROOT / ".build/gomodcache-sm2auth"),
               GOCACHE=str(ROOT / ".build/gocache-sm2auth"), GOPROXY="off", GOSUMDB="off",
               GOTOOLCHAIN="local", GOOS="linux", GOARCH="amd64", CGO_ENABLED="0")
    if hqc:
        oqs = ROOT / ".build/liboqs-gateway-hqc"
        if not (oqs / "lib/liboqs.a").is_file():
            raise RuntimeError("static liboqs is required for HQC")
        env.update(CGO_ENABLED="1", CGO_CFLAGS="-I" + str(oqs / "include"),
                   CGO_LDFLAGS="-L" + str(oqs / "lib") + " -loqs")
    return env


def build(bundle):
    bin_dir, config_dir, demo_dir, docs_dir = (
        bundle / "bin", bundle / "config", bundle / "demo", bundle / "docs")
    for directory in (bin_dir, config_dir, demo_dir, docs_dir, bundle / "validation"):
        directory.mkdir(parents=True, exist_ok=True)
    tls_go = TLS_ROOT / "bin/go"
    pq_go = PQ_ROOT / "bin/go"
    if not tls_go.is_file() or not pq_go.is_file():
        raise RuntimeError("local patched Go 1.22.12 and Go 1.25.1 toolchains are required")
    run([tls_go, "test", "./...", "-count=1", "-timeout=90s"], ROOT / "gateway",
        tls_env(), bundle / "validation/gateway-tests.log")
    run([tls_go, "vet", "./..."], ROOT / "gateway", tls_env(),
        bundle / "validation/gateway-vet.log")
    run([tls_go, "build", "-trimpath", "-ldflags=-s -w -X main.version=20261013-hybrid-mlkem",
         "-o", bin_dir / "pqc-gateway", "."], ROOT / "gateway", tls_env())
    run([tls_go, "test", "-tags=pq_hqc,netgo,osusergo", "./...", "-count=1", "-timeout=90s"],
        ROOT / "gateway", tls_env(True), bundle / "validation/gateway-hqc-tests.log")
    run([tls_go, "build", "-tags=pq_hqc,netgo,osusergo", "-trimpath",
         "-ldflags=-s -w -linkmode external -extldflags -static -X main.version=20261013-hybrid-mlkem-hqc",
         "-o", bin_dir / "pqc-gateway-hqc", "."], ROOT / "gateway", tls_env(True))
    pq_env = os.environ.copy()
    pq_env.update(GOROOT=str(PQ_ROOT), GOMODCACHE=str(Path.home() / "go/pkg/mod"),
                  GOCACHE=str(ROOT / ".build/gocache-certtool-stage2"), GOPROXY="off",
                  GOSUMDB="off", GOTOOLCHAIN="local", GOOS="linux", GOARCH="amd64",
                  CGO_ENABLED="0")
    run([pq_go, "test", "./...", "-count=1"], ROOT / "pqcert/configurable", pq_env,
        bundle / "validation/certtool-tests.log")
    run([pq_go, "vet", "./..."], ROOT / "pqcert/configurable", pq_env,
        bundle / "validation/certtool-vet.log")
    run([pq_go, "build", "-trimpath", "-ldflags=-s -w -X main.version=20261013-hybrid",
         "-o", bin_dir / "pqc-certtool", "."], ROOT / "pqcert/configurable", pq_env)
    for level in (44, 87):
        name = str(level)
        cert_config = json.loads((ROOT / "pqcert/configurable/examples" /
                                  ("tls-sm2-mldsa" + name + ".json")).read_text())
        cert_config["output_dir"] = "../demo/" + name
        cert_config_path = config_dir / ("certtool-" + name + ".json")
        cert_config_path.write_text(json.dumps(cert_config, ensure_ascii=False, indent=2) + "\n")
        run([bin_dir / "pqc-certtool", "check", "-config", cert_config_path])
        run([bin_dir / "pqc-certtool", "generate", "-config", cert_config_path],
            output=bundle / "validation" / ("certtool-generate-" + name + ".json"))
        run([bin_dir / "pqc-certtool", "verify", "-config", cert_config_path],
            output=bundle / "validation" / ("certtool-verify-" + name + ".json"))
        template = json.loads((ROOT / "gateway/examples" /
                               ("hybrid-" + name + ".json")).read_text())
        for field, suffix in (("cert", "server.crt"), ("key", "server.key"),
                              ("pq_key", "server.pq.key"), ("root_ca", "root.crt")):
            template[field] = "../demo/" + name + "/" + suffix
        template["client_ca"] = "../demo/" + name + "/root.crt"
        template["listen"] = "127.0.0.1:8443"
        (config_dir / ("demo-" + name + ".json")).write_text(
            json.dumps(template, ensure_ascii=False, indent=2) + "\n")
        run([bin_dir / "pqc-gateway", "check", "-config", config_dir / ("demo-" + name + ".json")])
        production = json.loads(json.dumps(template))
        production["listen"] = "0.0.0.0:8443"
        for field, suffix in (("cert", "server.crt"), ("key", "server.key"),
                              ("pq_key", "server.pq.key"), ("root_ca", "root.crt"),
                              ("client_ca", "root.crt")):
            production[field] = "../certs/" + name + "/" + suffix
        (config_dir / ("gateway-" + name + ".json")).write_text(
            json.dumps(production, ensure_ascii=False, indent=2) + "\n")
        production["kex"] = ["SM2HQC-128" if level == 44 else "SM2HQC-256"]
        (config_dir / ("gateway-" + name + "-hqc.json")).write_text(
            json.dumps(production, ensure_ascii=False, indent=2) + "\n")
    run([bin_dir / "pqc-gateway", "pki", "-out", demo_dir / "ecdsa",
         "-hosts", "gateway.factory.local", "-days", "365"])
    source = ROOT / "packaging/hybrid-runtime"
    for path in source.iterdir():
        if path.name in {"install.sh", "smoke.py", "README.md"}:
            shutil.copy2(path, bundle / path.name)
        elif path.is_dir() and path.name in {"docs", "systemd"}:
            shutil.copytree(path, bundle / path.name, dirs_exist_ok=True)
    for path in (bundle / "install.sh", bundle / "smoke.py"):
        path.chmod(0o755)
    result = run(["python3", bundle / "smoke.py", "--bundle", bundle])
    (bundle / "validation/local-smoke.json").write_text(result)
    binaries = {path.name: digest(path) for path in bin_dir.iterdir()}
    (bundle / "validation/build-info.json").write_text(json.dumps({
        "target": "Ubuntu 20.04 / Linux amd64", "binary_only": True,
        "gateway_authentication": "SM2+ML-DSA-44/87 TLS 1.3 mutual authentication",
        "default_key_exchange": "SM2MLKEM512/1024 (private-use TLS groups, FIPS 203 ML-KEM backend)",
        "hqc_binary_included": True, "local_smoke_passed": True,
        "target_machine_validation": "pending", "binaries_sha256": binaries,
    }, ensure_ascii=False, indent=2) + "\n")
    for path in demo_dir.rglob("*.key"):
        path.chmod(0o600)
    with (bundle / "SHA256SUMS").open("w") as out:
        for path in sorted(bundle.rglob("*")):
            if path.is_file() and path.name != "SHA256SUMS":
                out.write(digest(path) + "  " + path.relative_to(bundle).as_posix() + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replace", action="store_true", help="atomically replace an earlier generated ZIP")
    args = parser.parse_args()
    archive = ROOT / "dist" / (NAME + ".zip")
    if archive.exists() and not args.replace:
        raise SystemExit("refusing to overwrite " + str(archive))
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="hybrid-release-", dir=archive.parent) as temp:
        bundle = Path(temp) / NAME
        build(bundle)
        temporary_archive = Path(temp) / (NAME + ".zip")
        with zipfile.ZipFile(temporary_archive, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9, allowZip64=True) as output:
            for path in sorted(bundle.rglob("*")):
                if path.is_file():
                    output.write(path, arcname=str(Path(NAME) / path.relative_to(bundle)))
        os.replace(temporary_archive, archive)
    print(str(archive))
    print("sha256 " + digest(archive))


if __name__ == "__main__":
    main()
