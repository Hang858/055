#!/usr/bin/env python3
"""Run packaged binaries through ML-KEM, legacy Kyber and HQC mTLS probes."""
import argparse
import json
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def ready(address, proc):
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError("service exited before it became ready")
        try:
            with socket.create_connection(address, timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("service did not listen")


def run_case(bundle, level, family):
    name = str(level)
    auth = "sm2-mldsa-44" if level == 44 else "sm2-mldsa-87"
    group = {
        "mlkem": "SM2MLKEM512" if level == 44 else "SM2MLKEM1024",
        "kyber": "SM2Kyber512Draft00" if level == 44 else "SM2Kyber1024Draft00",
        "hqc": "SM2HQC-128" if level == 44 else "SM2HQC-256",
    }[family]
    gateway = bundle / "bin" / ("pqc-gateway-hqc" if family == "hqc" else "pqc-gateway")
    certs = bundle / "demo" / name
    backend_port, gateway_port = port(), port()
    while gateway_port == backend_port:
        gateway_port = port()
    with tempfile.TemporaryDirectory(prefix="pqc-gateway-smoke-") as temp:
        config = json.loads((bundle / "config" / ("demo-" + name + ".json")).read_text())
        config.update(listen="127.0.0.1:" + str(gateway_port),
                      upstream="http://127.0.0.1:" + str(backend_port), kex=[group])
        for field in ("cert", "key", "pq_key", "root_ca", "client_ca"):
            config[field] = str((bundle / "config" / config[field]).resolve())
        path = Path(temp) / "gateway.json"
        path.write_text(json.dumps(config))
        check = subprocess.run([str(gateway), "check", "-config", str(path)],
                               capture_output=True, text=True, timeout=20)
        if check.returncode != 0:
            raise RuntimeError("gateway check: " + check.stderr)
        backend = subprocess.Popen([str(gateway), "demo-backend", "-listen",
                                    "127.0.0.1:" + str(backend_port)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        server = None
        try:
            ready(("127.0.0.1", backend_port), backend)
            server = subprocess.Popen([str(gateway), "serve", "-config", str(path)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            ready(("127.0.0.1", gateway_port), server)
            base = [str(gateway), "probe", "-url", "https://127.0.0.1:" + str(gateway_port) + "/",
                    "-server-name", "gateway.factory.local", "-ca", str(certs / "root.crt"),
                    "-auth", auth, "-kex", group]
            missing = subprocess.run(base, capture_output=True, text=True, timeout=20)
            if missing.returncode == 0:
                raise RuntimeError("missing client certificate was accepted")
            probe = subprocess.run(base + ["-cert", str(certs / "client.crt"),
                                           "-key", str(certs / "client.key"),
                                           "-pq-key", str(certs / "client.pq.key")],
                                   capture_output=True, text=True, timeout=20)
            if probe.returncode != 0 or "factory-backend-ok" not in probe.stdout or (
                    "authenticated_signature=" + auth) not in probe.stderr or (
                    "negotiated_kex=" + group) not in probe.stderr:
                raise RuntimeError("valid probe failed: " + probe.stdout + probe.stderr)
            wrong_args = base[:]
            wrong_args[wrong_args.index("-auth") + 1] = (
                "sm2-mldsa-87" if level == 44 else "sm2-mldsa-44")
            wrong = subprocess.run(wrong_args, capture_output=True, text=True, timeout=20)
            if wrong.returncode == 0:
                raise RuntimeError("wrong hybrid signature level was accepted")
            traditional_args = base[:]
            traditional_args[traditional_args.index("-auth") + 1] = "ecdsa"
            traditional_args[traditional_args.index("-ca") + 1] = str(bundle / "demo/ecdsa/ca.crt")
            traditional = subprocess.run(traditional_args, capture_output=True, text=True, timeout=20)
            if traditional.returncode == 0:
                raise RuntimeError("traditional authentication downgrade was accepted")
            return {"level": name, "family": family, "group": group,
                    "missing_client_rejected": True, "mutual_tls": True,
                    "wrong_level_rejected": True, "traditional_downgrade_rejected": True,
                    "reported_signature": auth, "missing_client_error": missing.stderr.strip(),
                    "wrong_level_error": wrong.stderr.strip(),
                    "traditional_error": traditional.stderr.strip()}
        finally:
            for proc in (server, backend):
                if proc is not None:
                    proc.terminate()
                    try:
                        proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.communicate()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    cases = [run_case(bundle, level, family) for family in ("mlkem", "kyber", "hqc") for level in (44, 87)]
    print(json.dumps({"passed": True, "cases": cases}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
