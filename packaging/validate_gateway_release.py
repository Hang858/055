#!/usr/bin/env python3
"""Exercise the staged binaries through real sockets, without changing host services."""
import argparse
import hashlib
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
GROUPS = ["SM2Kyber512Draft00", "SM2Kyber768Draft00", "SM2Kyber1024Draft00",
          "X25519Kyber512Draft00", "X25519Kyber768Draft00", "X25519Kyber1024Draft00"]

HQC_GROUPS = ['X25519HQC-128', 'X25519HQC-256', 'SM2HQC-128', 'SM2HQC-256']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=ROOT / "dist/pqc-gateway-ubuntu20.04-amd64")
    parser.add_argument("--hqc", action="store_true", help="Require HQC and test its four groups")
    args = parser.parse_args()
    groups = GROUPS + (HQC_GROUPS if args.hqc else [])
    bundle = args.bundle.resolve()
    exe = bundle / "bin/pqc-gateway"
    records, processes, logs = [], [], []
    completed = False

    def call(label, command, success=True, expected=""):
        p = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=45)
        text = p.stdout + p.stderr
        ok = (p.returncode == 0) == success and expected in text
        records.append({"case": label, "passed": ok, "exit_code": p.returncode, "output": text})
        if not ok:
            raise RuntimeError(f"{label}: unexpected result {p.returncode}\n{text}")
        return p

    def port():
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    def start(command, listen_port, name, work):
        log = open(work / (name + ".log"), "w+")
        logs.append(log)
        process = subprocess.Popen(list(map(str, command)), stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        for _ in range(100):
            if process.poll() is not None:
                log.seek(0)
                raise RuntimeError(log.read())
            try:
                with socket.create_connection(("127.0.0.1", listen_port), timeout=.2):
                    return
            except OSError:
                time.sleep(.05)
        raise RuntimeError(f"{name} did not listen")

    try:
        with tempfile.TemporaryDirectory(prefix="gateway-release-test-") as tmp:
            work = Path(tmp)
            if args.hqc:
                call("HQC-enabled binary version", [exe,"version"], expected="HQC=true")
            backend_port, gateway_port = port(), port()
            certs = work / "certs"
            installer_input = work / "installer-input"
            installer_input.mkdir()
            shutil.copy2(bundle / "install.sh", installer_input / "install.sh")
            for directory in ("bin", "config", "docs", "systemd"):
                shutil.copytree(bundle / directory, installer_input / directory)
            manifest = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(installer_input)}\n"
                               for p in sorted(installer_input.rglob("*")) if p.is_file())
            (installer_input / "SHA256SUMS").write_text(manifest)
            install_prefix = work / "site-install"
            call("offline installer", ["bash", installer_input / "install.sh", install_prefix])
            call("installed binary version", [install_prefix / "bin/pqc-gateway", "version"], expected="pqc-gateway")
            if (install_prefix / "certs").exists() or (install_prefix / "certs-demo").exists():
                raise RuntimeError("installer deployed demo identities")
            call("installer refuses overwrite", ["bash", installer_input / "install.sh", install_prefix], success=False)
            with open(installer_input / "config/gateway.json", "a") as altered:
                altered.write("\n ")
            call("installer rejects modified package", ["bash", installer_input / "install.sh", work / "tampered-install"], success=False)
            call("generate fresh site PKI", [exe, "pki", "-out", certs, "-hosts", "localhost,127.0.0.1"])
            call("refuse PKI overwrite", [exe, "pki", "-out", certs], success=False)
            config = {"listen": f"127.0.0.1:{gateway_port}", "upstream": f"http://127.0.0.1:{backend_port}",
                      "cert": "certs/server.crt", "key": "certs/server.key", "kex": groups}
            cfg = work / "gateway.json"
            cfg.write_text(json.dumps(config))
            call("check relative config paths", [exe, "check", "-config", cfg], expected="OK")
            start([exe, "demo-backend", "-listen", f"127.0.0.1:{backend_port}"], backend_port, "backend", work)
            start([exe, "serve", "-config", cfg], gateway_port, "gateway", work)
            url = f"https://localhost:{gateway_port}/factory/acceptance?q=1"
            for group in groups:
                call("proxy " + group, [exe, "probe", "-url", url, "-ca", certs / "ca.crt",
                     "-kex", group, "-data", "factory-payload"], expected="factory-payload")
                text = records[-1]["output"]
                if "negotiated_kex=" + group not in text or "certificate_verified=true" not in text:
                    raise RuntimeError("missing verified PQ negotiation")
            call("reject hostname mismatch", [exe, "probe", "-url", url, "-ca", certs / "ca.crt",
                 "-server-name", "wrong.factory.local"], success=False)
            call("reject unrelated CA", [exe, "probe", "-url", url, "-ca", bundle / "certs-demo/ca.crt"], success=False)
            call("reject unsupported group", [exe, "probe", "-url", url, "-ca", certs / "ca.crt", "-kex", "X25519"], success=False)
            processes[-1].terminate(); processes[-1].wait(timeout=20)
            config["client_ca"] = "certs/ca.crt"
            cfg.write_text(json.dumps(config))
            start([exe, "serve", "-config", cfg], gateway_port, "gateway-mtls", work)
            call("mTLS refuses missing client", [exe, "probe", "-url", url, "-ca", certs / "ca.crt"], success=False)
            call("mTLS accepts valid client", [exe, "probe", "-url", url, "-ca", certs / "ca.crt",
                 "-cert", certs / "client.crt", "-key", certs / "client.key"], expected="factory-backend-ok")
            if args.hqc:
                for group in HQC_GROUPS:
                    call("mTLS " + group, [exe, "probe", "-url", url, "-ca", certs / "ca.crt",
                         "-kex", group, "-cert", certs / "client.crt", "-key", certs / "client.key"], expected="factory-backend-ok")
            processes[0].terminate(); processes[0].wait(timeout=10)
            call("upstream outage returns failure", [exe, "probe", "-url", url, "-ca", certs / "ca.crt",
                 "-cert", certs / "client.crt", "-key", certs / "client.key"], success=False, expected="502")
            for name in ("backend", "gateway", "gateway-mtls"):
                path = work / (name + ".log")
                if path.exists():
                    shutil.copy2(path, bundle / "validation" / (name + "-smoke.log"))
            completed = True
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
        for log in logs:
            log.close()
        report = {"tested_at_utc": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
                  "ubuntu_20_04_native_tested": False, "passed": completed and bool(records) and all(r["passed"] for r in records),
                  "cases": records}
        (bundle / "validation/release-smoke.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"Passed {len(records)} packaged-binary smoke cases")


if __name__ == "__main__":
    main()
