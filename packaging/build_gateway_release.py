#!/usr/bin/env python3
"""Build an offline Linux/amd64 gateway bundle from this checkout, without downloading."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
NAME = "pqc-gateway-ubuntu20.04-amd64"
TOOLS = ("pure-pq", "sm2", "x509-multi", "gen-pq-chain", "gen-sm2-chain")


def run(args, cwd=None, env=None, log=None):
    print("+", " ".join(map(str, args)), flush=True)
    if log:
        with open(log, "w") as output:
            subprocess.run(list(map(str, args)), cwd=cwd, env=env, check=True,
                           stdout=output, stderr=subprocess.STDOUT)
    else:
        subprocess.run(list(map(str, args)), cwd=cwd, env=env, check=True)


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def seal(bundle):
    if not (bundle / "validation/release-smoke.json").is_file():
        raise SystemExit("Run packaging/validate_gateway_release.py before sealing")
    if not json.loads((bundle / "validation/release-smoke.json").read_text())["passed"]:
        raise SystemExit("Packaged binary smoke tests did not pass")
    if not (bundle / "validation/gateway-tests.log").is_file():
        raise SystemExit("Save the gateway go test results before sealing")
    with open(bundle / "SHA256SUMS", "w") as output:
        for path in sorted(bundle.rglob("*")):
            if path.is_file() and path.name != "SHA256SUMS":
                output.write(f"{digest(path)}  {path.relative_to(bundle).as_posix()}\n")
    archive = bundle.parent / (NAME + ".tar.gz")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(bundle, arcname=NAME)
    archive.with_name(archive.name + ".sha256").write_text(f"{digest(archive)}  {archive.name}\n")
    print(f"Release: {archive} ({archive.stat().st_size / 1024 / 1024:.1f} MiB)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tls-goroot", type=Path, default=ROOT / ".build/go")
    parser.add_argument("--pq-goroot", type=Path,
                        default=Path.home() / "go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.1.linux-amd64")
    parser.add_argument("--modcache", type=Path, default=Path.home() / "go/pkg/mod")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / NAME)
    parser.add_argument("--with-hqc", action="store_true", help="Include the four HQC groups via static liboqs")
    parser.add_argument("--liboqs-prefix", type=Path, default=ROOT / ".build/liboqs-gateway-hqc")
    parser.add_argument("--seal", action="store_true")
    args = parser.parse_args()
    bundle = args.output.resolve()
    if args.seal:
        seal(bundle)
        return
    if bundle.exists():
        raise SystemExit(f"Refusing to overwrite existing bundle: {bundle}")
    tls_root, pq_root = args.tls_goroot.resolve(), args.pq_goroot.resolve()
    shutil.copytree(ROOT / "packaging/gateway", bundle)
    for d in ("bin", "validation", "source/gateway", "source/pqcert", "source/patches",
              "certificate-tools/bin", "certificate-tools/data", "certificate-tools/examples"):
        (bundle / d).mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(GOROOT=str(tls_root), GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off",
               GOCACHE=str(ROOT / ".build/gocache-gateway"), CGO_ENABLED="0", GOOS="linux", GOARCH="amd64")
    version = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    build_tags = []
    ldflags = f"-s -w -X main.version={version}"
    if args.with_hqc:
        oqs = args.liboqs_prefix.resolve()
        if not (oqs / "lib/liboqs.a").is_file():
            raise SystemExit("HQC build requires the static liboqs library")
        env.update(CGO_ENABLED="1", CGO_CFLAGS=f"-I{oqs / 'include'}", CGO_LDFLAGS=f"-L{oqs / 'lib'} -loqs")
        build_tags = ["-tags", "pq_hqc,netgo,osusergo"]
        ldflags += " -linkmode external -extldflags -static"
    run([tls_root / "bin/go", "build", *build_tags, "-trimpath", "-ldflags", ldflags,
         "-o", bundle / "bin/pqc-gateway", "."], ROOT / "gateway", env)
    for path in (ROOT / "gateway").iterdir():
        if path.suffix == ".go" or path.name == "go.mod":
            shutil.copy2(path, bundle / "source/gateway" / path.name)
    shutil.copytree(ROOT / "patches", bundle / "source/patches", dirs_exist_ok=True)
    for script in ("build_gateway_release.py", "validate_gateway_release.py"):
        shutil.copy2(ROOT / "packaging" / script, bundle / "source" / script)
    # Preserve the actual compiler source, including local PQ vendor additions, rather than claiming
    # that the diff alone reconstructs any unrecorded historical edits in this checkout.
    with tarfile.open(bundle / "source/patched-go1.22.12-source.tar.gz", "w:gz") as tar:
        def source_filter(info):
            parts = Path(info.name).parts
            if any(p in {".git", "tls1", "vendor1", ".DS_Store"} for p in parts):
                return None
            return info
        for name in ("src", "lib", "VERSION", "go.env", "LICENSE", "PATENTS", "README.md"):
            tar.add(tls_root / name, arcname="go/" + name, filter=source_filter)
    shutil.copy2(ROOT / "pqcert/data/public_keys.txt", bundle / "certificate-tools/data/")
    shutil.copy2(ROOT / "pqcert/data/public_keys.txt", bundle / "source/pqcert/public_keys.txt")
    pq_env = env.copy()
    pq_env.update(GOROOT=str(pq_root), GOMODCACHE=str(args.modcache.resolve()), CGO_ENABLED="0")
    for name in TOOLS:
        dest = bundle / "source/pqcert" / name
        dest.mkdir()
        for filename in ("main.go", "go.mod", "go.sum"):
            shutil.copy2(ROOT / "pqcert" / name / filename, dest / filename)
        run([pq_root / "bin/go", "mod", "vendor"], dest, pq_env,
            bundle / "validation" / (name + "-vendor.log"))
        run([pq_root / "bin/go", "build", "-mod=vendor", "-trimpath", "-ldflags=-s -w",
             "-o", bundle / "certificate-tools/bin" / name, "."], dest, pq_env,
            bundle / "validation" / (name + "-build.log"))
    for filename in ("install.sh", "certificate-tools.sh"):
        (bundle / filename).chmod(0o755)
    run([bundle / "bin/pqc-gateway", "pki", "-out", bundle / "certs-demo",
         "-hosts", "localhost,127.0.0.1,::1", "-days", "365"])
    for name in TOOLS:
        run(["bash", bundle / "certificate-tools.sh", name,
             bundle / "certificate-tools/examples" / name],
            log=bundle / "validation" / (name + "-generation.log"))
    # Only retain public license text and compiler source; no existing working certificates or keys.
    provenance = {
        "version": version, "target": "Ubuntu 20.04 linux/amd64",
        "build_host": platform.platform(), "cgo_enabled": args.with_hqc,
        "gateway_source": "gateway/", "tls_goroot_version": (tls_root / "VERSION").read_text().strip(),
        "pq_go_version": (pq_root / "VERSION").read_text().strip(),
        "browser_included": False, "hqc_included": args.with_hqc,
        "authentication": "ECDSA-P256 runtime certificates; optional mTLS",
        "pqc": "Project Kyber Draft00 and HQC hybrid key exchange" if args.with_hqc else "Project Kyber Draft00 hybrid key exchange; not final ML-KEM",
        "tests": "See gateway-tests.log and release-smoke.json; Ubuntu 20.04 on-site validation required",
    }
    (bundle / "validation/build-info.json").write_text(json.dumps(provenance, ensure_ascii=False, indent=2) + "\n")
    for path in bundle.rglob("*"):
        if path.is_file() and (path.suffix == ".key" or "key" in path.name and path.suffix in {".bin", ".pem"}):
            path.chmod(0o600)
    print("Staged:", bundle)
    print("Next: validate_gateway_release.py; then rerun this command with --seal")


if __name__ == "__main__":
    main()
