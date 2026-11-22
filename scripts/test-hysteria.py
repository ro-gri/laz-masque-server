#!/usr/bin/env python3
"""Run isolated loopback Hysteria2 interop. No TUN, privileges or host routing.

Supply an independently verified Hysteria binary via HYSTERIA_BIN. This script
never downloads software or uses deployment configuration. Temporary keys,
authentication and child processes are removed on success and failure.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time


def port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", action="store_true", help="run the network benchmark through the isolated client")
    parser.add_argument("--release", action="store_true", help="use release-profile interop tests")
    args = parser.parse_args()
    binary = str(Path(os.environ["HYSTERIA_BIN"]).resolve(strict=True))
    root = Path(__file__).resolve().parent.parent
    children = []
    secret = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="masque-hysteria-") as directory:
        work = Path(directory)
        try:
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(work / "key.pem"), "-out", str(work / "cert.pem"),
                "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.chmod(work / "key.pem", 0o600)
            server_port = port(socket.SOCK_DGRAM)
            socks_port = port(socket.SOCK_STREAM)
            configs = {
                "server": {"listen": f"127.0.0.1:{server_port}",
                           "tls": {"cert": str(work / "cert.pem"), "key": str(work / "key.pem")},
                           "auth": {"type": "password", "password": secret}},
                "client": {"server": f"127.0.0.1:{server_port}", "auth": secret,
                           "tls": {"sni": "localhost", "ca": str(work / "cert.pem")},
                           "fastOpen": False,
                           "socks5": {"listen": f"127.0.0.1:{socks_port}", "disableUDP": False}},
            }
            for role, config in configs.items():
                path = work / f"{role}.json"
                path.write_text(json.dumps(config))
                path.chmod(0o600)
                log = (work / f"{role}.log").open("wb")
                try:
                    children.append(subprocess.Popen([binary, role, "--disable-update-check", "--log-level", "debug", "-c", str(path)], stdout=log, stderr=log))
                finally:
                    log.close()
                if role == "server":
                    time.sleep(0.3)
            deadline = time.monotonic() + 15
            while True:
                if any(child.poll() is not None for child in children):
                    raise RuntimeError("isolated Hysteria process exited during setup")
                try:
                    with socket.create_connection(("127.0.0.1", socks_port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("isolated Hysteria SOCKS listener did not become ready") from None
                    time.sleep(0.1)
            env = dict(os.environ, MASQUE_TEST_HYSTERIA_SOCKS=f"127.0.0.1:{socks_port}")
            if args.benchmark:
                env["MASQUE_BENCH_SOCKS5_ADDR"] = f"127.0.0.1:{socks_port}"
                env["MASQUE_BENCH_SOCKS5_UDP_MAX_PACKET_SIZE"] = "4000"
                subprocess.run(["bash", "scripts/network-bench.sh"], cwd=root, env=env, check=True, timeout=1800)
            else:
                subprocess.run(["cargo", "test", *(["--release"] if args.release else []), "--locked", "--test", "http2_connect", "--test", "client_cert_connect_ip",
                                "hysteria2_real", "--", "--ignored"], cwd=root, env=env, check=True, timeout=600)
        except Exception:
            for role in ("server", "client"):
                path = work / f"{role}.log"
                if path.exists():
                    print(path.read_text(errors="replace")[-8192:].replace(secret, "[test credential]").replace(str(work), "[test directory]"), flush=True)
            raise
        finally:
            for child in children:
                if child.poll() is None:
                    child.terminate()
            for child in children:
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()


if __name__ == "__main__":
    main()
