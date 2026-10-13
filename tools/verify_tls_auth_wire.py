#!/usr/bin/env python3
"""Record packaged gateway handshakes through a local byte-for-byte TCP relay."""

import argparse
import errno
import json
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import tls_hello_check as hello


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_listening(port, proc):
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError("service exited before listening")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("service did not listen")


def relay_once(listener, gateway_port, client_path, server_path, errors):
    try:
        incoming, _ = listener.accept()
        with incoming, socket.create_connection(("127.0.0.1", gateway_port)) as outgoing:
            def forward(source, target, path):
                with path.open("wb") as record:
                    while data := source.recv(65536):
                        record.write(data)
                        target.sendall(data)
                try:
                    target.shutdown(socket.SHUT_WR)
                except OSError as exc:
                    if exc.errno != errno.ENOTCONN:
                        raise

            other = threading.Thread(target=forward, args=(incoming, outgoing, client_path))
            other.start()
            forward(outgoing, incoming, server_path)
            other.join(timeout=5)
            if other.is_alive():
                raise RuntimeError("client relay did not finish")
    except Exception as exc:
        errors.append(str(exc))
    finally:
        listener.close()


def client_hello_extensions(body):
    pos = 34
    pos += 1 + body[pos]
    suites_len = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2 + suites_len
    pos += 1 + body[pos]
    return hello.parse_extensions(body[pos:])


def schemes(extension):
    if len(extension) < 2:
        return []
    size = int.from_bytes(extension[:2], "big")
    if size != len(extension) - 2 or size % 2:
        raise RuntimeError("malformed signature algorithms extension")
    return [struct.unpack("!H", extension[i:i + 2])[0]
            for i in range(2, len(extension), 2)]


def run_case(bundle, output, level, hqc):
    name = str(level)
    auth = "sm2-mldsa-44" if level == 44 else "sm2-mldsa-87"
    codepoint = 0xfea0 if level == 44 else 0xfea1
    group = ("SM2HQC-128" if level == 44 else "SM2HQC-256") if hqc else (
        "SM2Kyber512Draft00" if level == 44 else "SM2Kyber1024Draft00")
    executable = bundle / "bin" / ("pqc-gateway-hqc" if hqc else "pqc-gateway")
    certs = bundle / "demo" / name
    backend_port = free_port()
    gateway_port = free_port()
    while gateway_port == backend_port:
        gateway_port = free_port()
    tag = f"{name}-{'hqc' if hqc else 'kyber'}"
    config = json.loads((bundle / "config" / f"demo-{name}.json").read_text())
    config.update(listen=f"127.0.0.1:{gateway_port}",
                  upstream=f"http://127.0.0.1:{backend_port}", kex=[group])
    for field in ("cert", "key", "pq_key", "root_ca", "client_ca"):
        config[field] = str((bundle / "config" / config[field]).resolve())
    config_path = output / f"{tag}-config.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    backend = subprocess.Popen([str(executable), "demo-backend", "-listen",
                                f"127.0.0.1:{backend_port}"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    server = None
    try:
        wait_listening(backend_port, backend)
        server = subprocess.Popen([str(executable), "serve", "-config", str(config_path)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_listening(gateway_port, server)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            relay_port = listener.getsockname()[1]
            client_path = output / f"{tag}-client.tls"
            server_path = output / f"{tag}-server.tls"
            errors = []
            relay = threading.Thread(target=relay_once, args=(
                listener, gateway_port, client_path, server_path, errors))
            relay.start()
            probe = subprocess.run([str(executable), "probe", "-url",
                                    f"https://127.0.0.1:{relay_port}/", "-server-name",
                                    "gateway.factory.local", "-ca", str(certs / "root.crt"),
                                    "-auth", auth, "-kex", group,
                                    "-cert", str(certs / "client.crt"),
                                    "-key", str(certs / "client.key"),
                                    "-pq-key", str(certs / "client.pq.key")],
                                   capture_output=True, text=True, timeout=30)
            relay.join(timeout=5)
            if relay.is_alive() or errors:
                raise RuntimeError("relay failed: " + repr(errors))
        if probe.returncode or "factory-backend-ok" not in probe.stdout:
            raise RuntimeError("probe failed: " + probe.stdout + probe.stderr)
        client_msgs = hello.parse_handshake_messages(client_path.read_bytes())
        server_msgs = hello.parse_handshake_messages(server_path.read_bytes())
        client_bodies = [body for kind, body in client_msgs if kind == 1]
        server_bodies = [body for kind, body in server_msgs if kind == 2]
        if not client_bodies or not server_bodies:
            raise RuntimeError("incomplete ClientHello/ServerHello capture")
        ch = hello.parse_client_hello(client_bodies[0])
        sh = hello.parse_server_hello(server_bodies[-1])
        ext = client_hello_extensions(client_bodies[0])
        advertised = schemes(ext.get(13, b""))
        cert_advertised = schemes(ext.get(50, b""))
        if ch is None or sh is None or sh["key_share"] is None:
            raise RuntimeError("incomplete ClientHello/ServerHello capture")
        if advertised != [codepoint] or sh["key_share"][0] not in ch["supported_groups"]:
            raise RuntimeError("unexpected signature or key exchange negotiation")
        if f"codepoint=0x{codepoint:04x}" not in probe.stderr:
            raise RuntimeError("verified CertificateVerify scheme was not reported")
        return {"case": tag, "signature_algorithms": [f"0x{x:04x}" for x in advertised],
                "signature_algorithms_cert": [f"0x{x:04x}" for x in cert_advertised],
                "client_key_share": ch["key_shares"],
                "server_key_share": sh["key_share"],
                "verified_certificate_verify": f"0x{codepoint:04x}",
                "client_trace": client_path.name, "server_trace": server_path.name}
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
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    cases = [run_case(bundle, output, level, hqc)
             for hqc in (False, True) for level in (44, 87)]
    result = {"local_capture_passed": True, "capture_method": "local TCP relay, raw TLS records",
              "cases": cases}
    (output / "wire-report.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1)
