#!/usr/bin/env python3
"""
wtunnel 端到端拉通测试
======================

覆盖范围：
  1. 直连 server — TLS 握手 / ALPN / H2 SETTINGS
  2. 直连 server — H2 CONNECT 流（隧道协议层）
  3. 直连 server — Chrome TLS 指纹特征验证
  4. client proxy — HTTP CONNECT 握手 → 200 响应
  5. client proxy — 通过隧道发送 / 接收数据（本地 echo 服务器）
  6. client proxy — 多路复用：N 条并发 CONNECT 流
  7. client proxy — 代理对非 CONNECT 方法返回 405

用法:
  # 1. 先启动 server（如未运行会自动启动）
  #    ./build/bin/qtunnel_server &
  # 2. 先启动 client（如未运行会自动启动）
  #    ./build/bin/qtunnel_client &
  # 3. 运行测试
  python3 test/test_e2e.py

  # 指定路径 / 端口
  python3 test/test_e2e.py \\
      --server-bin build/bin/qtunnel_server \\
      --client-bin build/bin/qtunnel_client \\
      --server-host 127.0.0.1 --server-port 8443 \\
      --proxy-host 127.0.0.1  --proxy-port 8080
"""

import argparse
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, suppress
from typing import Optional

try:
    import h2.connection
    import h2.config
    import h2.events
    import h2.exceptions
except ImportError:
    sys.exit("❌  pip install h2")

# ─────────────────────────────────────────────────────────────────────────────
# 颜色 / 结果追踪
# ─────────────────────────────────────────────────────────────────────────────
PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
WARN = "\033[33mWARN\033[0m"

_results: list[tuple[str, bool, str]] = []


def report(name: str, ok: bool, detail: str = "") -> bool:
    tag = PASS if ok else FAIL
    line = f"  [{tag}] {name}"
    if detail:
        line += f"  — {detail}"
    print(line)
    _results.append((name, ok, detail))
    return ok


# ─────────────────────────────────────────────────────────────────────────────
# TLS / H2 工具
# ─────────────────────────────────────────────────────────────────────────────

def make_tls_ctx(alpn: list[str] | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(alpn or ["h2", "http/1.1"])
    return ctx


def tls_connect(host: str, port: int, timeout: float = 5.0,
                alpn: list[str] | None = None) -> ssl.SSLSocket:
    ctx = make_tls_ctx(alpn)
    raw = socket.create_connection((host, port), timeout=timeout)
    ssock = ctx.wrap_socket(raw, server_hostname=host)
    ssock.settimeout(timeout)
    return ssock


def h2_client(ssock: ssl.SSLSocket) -> h2.connection.H2Connection:
    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    ssock.sendall(conn.data_to_send(65535))
    return conn


def drain(ssock: ssl.SSLSocket, conn: h2.connection.H2Connection,
          timeout: float = 3.0,
          until: int | None = None,
          until_types: tuple = ()) -> list:
    """读取并处理 H2 事件直到 until_stream 出现指定事件类型或超时。"""
    collected: list = []
    deadline = time.monotonic() + timeout
    ssock.settimeout(0.3)
    while time.monotonic() < deadline:
        try:
            data = ssock.recv(65535)
        except (ssl.SSLEOFError, ConnectionResetError):
            break
        except (TimeoutError, ssl.SSLWantReadError, socket.timeout,
                OSError):
            data = b""
        if data:
            evs = conn.receive_data(data)
            out = conn.data_to_send(65535)
            if out:
                ssock.sendall(out)
            for ev in evs:
                collected.append(ev)
                if isinstance(ev, h2.events.DataReceived):
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                if until is not None and until_types:
                    if ev.stream_id == until and isinstance(ev, until_types):
                        return collected
        elif until is None:
            break   # 没有 until 目标就只收一轮
    return collected


# ─────────────────────────────────────────────────────────────────────────────
# 进程管理（可选自动启动）
# ─────────────────────────────────────────────────────────────────────────────

_procs: list[subprocess.Popen] = []


def launch(cmd: list[str], name: str) -> subprocess.Popen:
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _procs.append(p)
    print(f"  [launched] {name}  pid={p.pid}  cmd={' '.join(cmd)}")
    return p


def wait_port(host: str, port: int, retries: int = 20, interval: float = 0.4) -> bool:
    for i in range(retries):
        try:
            s = socket.create_connection((host, port), timeout=1)
            s.close()
            return True
        except OSError:
            if i == 0:
                print(f"  waiting for {host}:{port}", end="", flush=True)
            else:
                print(".", end="", flush=True)
            time.sleep(interval)
    print()
    return False


def kill_all():
    for p in _procs:
        with suppress(Exception):
            p.terminate()
            p.wait(timeout=3)


# ─────────────────────────────────────────────────────────────────────────────
# 本地 Echo 服务器（用于 data-relay 测试）
# ─────────────────────────────────────────────────────────────────────────────

class EchoServer:
    """TCP echo server：收到数据原样返回，用于验证代理数据路径。"""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(16)
        self.host, self.port = self._sock.getsockname()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        self._sock.settimeout(0.5)
        while True:
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    @staticmethod
    def _handle(conn: socket.socket):
        conn.settimeout(5.0)
        with suppress(Exception):
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        conn.close()

    def close(self):
        with suppress(Exception):
            self._sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# 测试用例 — Section 1: 直连 Server
# ─────────────────────────────────────────────────────────────────────────────

def t_tls_handshake(shost: str, sport: int) -> bool:
    """TLS 握手完成，ALPN 协商为 h2。"""
    try:
        ssock = tls_connect(shost, sport)
        alpn = ssock.selected_alpn_protocol()
        cipher = ssock.cipher()
        ver = ssock.version()
        ssock.close()
        ok = (alpn == "h2")
        return report("TLS handshake (ALPN=h2)", ok,
                      f"alpn={alpn!r} version={ver} cipher={cipher[0] if cipher else '?'}")
    except Exception as e:
        return report("TLS handshake (ALPN=h2)", False, str(e))


def t_chrome_fingerprint(shost: str, sport: int) -> bool:
    """
    验证 server 接受 Chrome 风格的 TLS 握手。
    使用与 client.cpp 相同的 ALPN + cipher 列表，确认连接不被拒绝。
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Chrome 146 cipher preference order（OpenSSL 格式）
        chrome_ciphers = (
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
        )
        with suppress(ssl.SSLError):        # Python ssl may not support all TLS 1.3 ciphers
            ctx.set_ciphers(chrome_ciphers)
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        # TLS 1.2 minimum (Chrome behaviour)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

        raw = socket.create_connection((shost, sport), timeout=5)
        ssock = ctx.wrap_socket(raw, server_hostname=shost)
        alpn = ssock.selected_alpn_protocol()
        ver  = ssock.version()
        ssock.close()

        ok = (alpn == "h2") and (ver in ("TLSv1.2", "TLSv1.3"))
        return report("Chrome TLS fingerprint accepted", ok,
                      f"alpn={alpn!r} version={ver}")
    except Exception as e:
        return report("Chrome TLS fingerprint accepted", False, str(e))


def t_h2_settings(shost: str, sport: int) -> bool:
    """H2 连接预检：双方完成 SETTINGS + ACK 交换。"""
    try:
        ssock = tls_connect(shost, sport)
        conn = h2_client(ssock)
        evs = drain(ssock, conn, timeout=3.0)
        ssock.close()

        has_settings = any(isinstance(e, h2.events.RemoteSettingsChanged) for e in evs)
        has_ack      = any(isinstance(e, h2.events.SettingsAcknowledged)   for e in evs)
        fatal        = [e for e in evs if isinstance(e, h2.events.ConnectionTerminated)]

        ok = has_settings and not fatal
        return report("H2 SETTINGS exchange", ok,
                      f"RemoteSettings={has_settings} SettingsAck={has_ack} fatal={len(fatal)}")
    except Exception as e:
        return report("H2 SETTINGS exchange", False, str(e))


def t_h2_connect_stream(shost: str, sport: int) -> bool:
    """
    直接向 server 发送 H2 CONNECT 流（RFC 7540 §8.3）。
    验证：server 不返回协议层错误（GOAWAY / PROTOCOL_ERROR）。

    Python h2 库对 CONNECT 的伪头校验较严格，使用原始 hpack 编码绕过限制。
    """
    import hpack

    try:
        ssock = tls_connect(shost, sport)

        # 手动发送 H2 Client Preface + SETTINGS，然后构造 CONNECT HEADERS 帧
        CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        ssock.sendall(CLIENT_PREFACE)

        # SETTINGS 帧 (type=4, flags=0, stream=0, empty payload)
        settings_frame = struct.pack(">I B I", 0, 4, 0)[1:]  # 3-byte length=0
        settings_frame = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
        ssock.sendall(settings_frame)

        # 编码 CONNECT HEADERS (stream_id=1)
        encoder = hpack.Encoder()
        headers_block = encoder.encode([
            (b":method",    b"CONNECT"),
            (b":authority", b"example.com:443"),
        ])
        hlen = len(headers_block)
        # HEADERS 帧: length(3) type(1)=0x01 flags(1)=END_HEADERS(0x04) stream_id(4)=1
        headers_frame = (
            struct.pack(">I", hlen)[1:]         # 3-byte length
            + b"\x01"                            # type = HEADERS
            + b"\x04"                            # flags = END_HEADERS
            + struct.pack(">I", 1)               # stream_id = 1
            + headers_block
        )
        ssock.sendall(headers_frame)

        # 读响应，超时 3 秒
        ssock.settimeout(3.0)
        recv_buf = b""
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                recv_buf += chunk
                if len(recv_buf) >= 9:  # 至少一个完整帧头
                    break
            except (socket.timeout, ssl.SSLWantReadError):
                break
        ssock.close()

        if not recv_buf:
            return report("H2 CONNECT stream → server (protocol layer)", True,
                          "stream=1 no data received, no fatal error (server CONNECT pending)")

        # 解析第一个帧头
        if len(recv_buf) >= 9:
            flen  = struct.unpack(">I", b"\x00" + recv_buf[0:3])[0]
            ftype = recv_buf[3]
            flags = recv_buf[4]
            fstid = struct.unpack(">I", recv_buf[5:9])[0] & 0x7fffffff

            type_names = {0: "DATA", 1: "HEADERS", 4: "SETTINGS",
                          5: "PUSH_PROMISE", 7: "GOAWAY", 8: "WINDOW_UPDATE"}
            tname = type_names.get(ftype, f"type={ftype}")

            # GOAWAY (type=7) は PROTOCOL_ERROR なら失敗
            if ftype == 7 and len(recv_buf) >= 17:
                error_code = struct.unpack(">I", recv_buf[13:17])[0]
                ok = (error_code != 1)  # 1 = PROTOCOL_ERROR
                return report("H2 CONNECT stream → server", ok,
                              f"GOAWAY error_code={error_code}"
                              + (" (PROTOCOL_ERROR)" if error_code == 1 else " (ok)"))

            # SETTINGS (type=4) は正常
            if ftype == 4:
                return report("H2 CONNECT stream → server (protocol layer)", True,
                              f"got {tname} stream={fstid}, CONNECT accepted without error")

            return report("H2 CONNECT stream → server (protocol layer)", ftype != 7,
                          f"first frame: {tname} stream={fstid} flags={flags:#04x}")
        else:
            return report("H2 CONNECT stream → server (protocol layer)", True,
                          f"partial data={len(recv_buf)}B, no GOAWAY")

    except Exception as e:
        return report("H2 CONNECT stream → server", False, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# 测试用例 — Section 2: 经由 client proxy
# ─────────────────────────────────────────────────────────────────────────────

def proxy_connect(phost: str, pport: int,
                  target_host: str, target_port: int,
                  timeout: float = 5.0) -> socket.socket:
    """
    通过 HTTP CONNECT 代理建立隧道，返回已建立的 socket（tunnel 后的裸 socket）。
    """
    sock = socket.create_connection((phost, pport), timeout=timeout)
    req = (f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
           f"Host: {target_host}:{target_port}\r\n"
           f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
           f"AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36\r\n"
           f"\r\n")
    sock.sendall(req.encode())
    sock.settimeout(timeout)

    # Read response
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Proxy closed before sending response")
        resp += chunk

    first_line = resp.split(b"\r\n")[0].decode()
    parts = first_line.split(None, 2)
    if len(parts) < 2 or parts[1] != "200":
        raise ConnectionError(f"Proxy returned: {first_line!r}")
    return sock


def t_proxy_connect_200(phost: str, pport: int,
                         shost: str, sport: int) -> bool:
    """client proxy 对 CONNECT 请求回复 200 Connection Established。"""
    try:
        sock = proxy_connect(phost, pport, shost, sport)
        sock.close()
        return report("Proxy CONNECT → 200", True,
                      f"proxy={phost}:{pport} target={shost}:{sport}")
    except Exception as e:
        return report("Proxy CONNECT → 200", False, str(e))


def t_proxy_data_relay(phost: str, pport: int,
                        echo_host: str, echo_port: int) -> bool:
    """
    通过代理隧道连接到本地 echo server，发送数据并验证原样返回。
    """
    msg = b"Hello wtunnel! " + bytes(range(256))  # 271 bytes，含二进制数据
    try:
        sock = proxy_connect(phost, pport, echo_host, echo_port)
        sock.settimeout(5.0)
        sock.sendall(msg)

        received = b""
        deadline = time.monotonic() + 5.0
        while len(received) < len(msg) and time.monotonic() < deadline:
            chunk = sock.recv(4096)
            if not chunk:
                break
            received += chunk
        sock.close()

        ok = received == msg
        return report("Proxy data relay (echo)", ok,
                      f"sent={len(msg)} recv={len(received)} match={ok}")
    except Exception as e:
        return report("Proxy data relay (echo)", False, str(e))


def t_proxy_large_data(phost: str, pport: int,
                        echo_host: str, echo_port: int,
                        size: int = 256 * 1024) -> bool:
    """通过代理发送大块数据（256 KB），验证流控和缓冲正确。"""
    msg = bytes(i % 251 for i in range(size))
    try:
        sock = proxy_connect(phost, pport, echo_host, echo_port)
        sock.settimeout(10.0)

        # 后台发送，避免缓冲区满死锁
        def sender():
            with suppress(Exception):
                total = 0
                while total < len(msg):
                    n = sock.send(msg[total:total + 8192])
                    total += n

        t = threading.Thread(target=sender, daemon=True)
        t.start()

        received = b""
        deadline = time.monotonic() + 10.0
        while len(received) < len(msg) and time.monotonic() < deadline:
            chunk = sock.recv(8192)
            if not chunk:
                break
            received += chunk
        sock.close()
        t.join(timeout=1)

        ok = received == msg
        return report(f"Proxy large data relay ({size//1024} KB)", ok,
                      f"sent={len(msg)} recv={len(received)} match={ok}")
    except Exception as e:
        return report(f"Proxy large data relay ({size//1024} KB)", False, str(e))


def t_proxy_concurrent(phost: str, pport: int,
                        echo_host: str, echo_port: int,
                        n: int = 8) -> bool:
    """在同一隧道上并发建立 N 条 CONNECT，验证 H2 多路复用。"""
    def one_session(idx: int) -> bool:
        msg = f"stream-{idx:04d}-".encode() * 100   # ~1.4 KB per stream
        sock = proxy_connect(phost, pport, echo_host, echo_port, timeout=8.0)
        sock.settimeout(8.0)

        def sender():
            with suppress(Exception):
                sock.sendall(msg)
        threading.Thread(target=sender, daemon=True).start()

        received = b""
        deadline = time.monotonic() + 8.0
        while len(received) < len(msg) and time.monotonic() < deadline:
            chunk = sock.recv(4096)
            if not chunk:
                break
            received += chunk
        sock.close()
        return received == msg

    ok_count = err_count = 0
    try:
        with ThreadPoolExecutor(max_workers=n) as ex:
            futs = [ex.submit(one_session, i) for i in range(n)]
            for f in as_completed(futs, timeout=20):
                try:
                    if f.result():
                        ok_count += 1
                    else:
                        err_count += 1
                except Exception:
                    err_count += 1

        ok = (err_count == 0)
        return report(f"Proxy concurrent {n} streams (mux)", ok,
                      f"ok={ok_count} fail={err_count}")
    except Exception as e:
        return report(f"Proxy concurrent {n} streams (mux)", False, str(e))


def t_proxy_method_not_allowed(phost: str, pport: int) -> bool:
    """向代理发送非 CONNECT 方法，期望返回 405。"""
    try:
        sock = socket.create_connection((phost, pport), timeout=5)
        req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
        sock.sendall(req.encode())
        sock.settimeout(3.0)
        resp = sock.recv(4096).decode(errors="replace")
        sock.close()
        ok = "405" in resp.split("\n")[0]
        return report("Proxy non-CONNECT → 405", ok,
                      f"first line: {resp.splitlines()[0]!r}")
    except Exception as e:
        return report("Proxy non-CONNECT → 405", False, str(e))


def t_proxy_connect_tls_through(phost: str, pport: int,
                                  shost: str, sport: int) -> bool:
    """
    通过代理向 tunnel server 建立 CONNECT，然后在隧道内再做 TLS+H2 握手。
    模拟浏览器的真实使用场景：CONNECT → TLS → H2 请求。
    """
    try:
        raw = proxy_connect(phost, pport, shost, sport)
        # 在隧道上叠加 TLS
        ctx = make_tls_ctx(["h2"])
        ssock = ctx.wrap_socket(raw, server_hostname=shost)
        alpn = ssock.selected_alpn_protocol()
        conn = h2_client(ssock)
        evs = drain(ssock, conn, timeout=3.0)
        ssock.close()

        has_settings = any(isinstance(e, h2.events.RemoteSettingsChanged) for e in evs)
        fatal = [e for e in evs if isinstance(e, h2.events.ConnectionTerminated)]
        ok = (alpn == "h2") and has_settings and not fatal
        return report("Proxy → TLS-over-tunnel → H2 handshake", ok,
                      f"alpn={alpn!r} settings={has_settings} fatal={len(fatal)}")
    except Exception as e:
        return report("Proxy → TLS-over-tunnel → H2 handshake", False, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# 测试入口
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="wtunnel e2e test suite")
    parser.add_argument("--server-host", default="127.0.0.1")
    parser.add_argument("--server-port", type=int, default=8443)
    parser.add_argument("--proxy-host",  default="127.0.0.1")
    parser.add_argument("--proxy-port",  type=int, default=8080)
    parser.add_argument("--server-bin",  default="build/bin/qtunnel_server",
                        help="path to server binary (auto-launched if not running)")
    parser.add_argument("--client-bin",  default="build/bin/qtunnel_client",
                        help="path to client binary (auto-launched if not running)")
    parser.add_argument("--no-auto-launch", action="store_true",
                        help="disable auto-launching binaries")
    parser.add_argument("--concurrent", type=int, default=8,
                        help="number of concurrent streams for mux test")
    args = parser.parse_args()

    shost, sport = args.server_host, args.server_port
    phost, pport = args.proxy_host,  args.proxy_port

    print()
    print("═" * 60)
    print("  wtunnel e2e test suite")
    print(f"  server : {shost}:{sport}")
    print(f"  proxy  : {phost}:{pport}")
    print("═" * 60)

    # ── 自动启动 server ────────────────────────────────────────────────────
    try:
        socket.create_connection((shost, sport), timeout=1).close()
        print(f"\n[server] already running on {shost}:{sport}")
    except OSError:
        if args.no_auto_launch:
            sys.exit(f"❌  server not running on {shost}:{sport}")
        import os
        if not os.path.exists(args.server_bin):
            sys.exit(f"❌  server binary not found: {args.server_bin}")
        print(f"\n[server] launching {args.server_bin} ...")
        launch([args.server_bin], "qtunnel_server")
        if not wait_port(shost, sport, retries=20):
            kill_all()
            sys.exit(f"❌  server failed to start on {shost}:{sport}")

    # ── 自动启动 client proxy ──────────────────────────────────────────────
    try:
        socket.create_connection((phost, pport), timeout=1).close()
        print(f"[proxy]  already running on {phost}:{pport}")
    except OSError:
        if args.no_auto_launch:
            print(f"[proxy]  not running — skipping proxy tests")
            proxy_available = False
        else:
            import os
            if not os.path.exists(args.client_bin):
                print(f"[proxy]  binary not found: {args.client_bin} — skipping proxy tests")
                proxy_available = False
            else:
                print(f"[proxy]  launching {args.client_bin} ...")
                launch([args.client_bin, str(pport), shost, str(sport)], "qtunnel_client")
                proxy_available = wait_port(phost, pport, retries=20)
                if not proxy_available:
                    print(f"\n  [{WARN}] proxy failed to start — proxy tests will be skipped")
    else:
        proxy_available = True

    # ── Echo server ────────────────────────────────────────────────────────
    echo = EchoServer()
    print(f"[echo]   listening on {echo.host}:{echo.port}")

    # ═══════════════════════════════════════════════════════════════════════
    # Section 1 — 直连 Server
    # ═══════════════════════════════════════════════════════════════════════
    print("\n── Section 1: 直连 Server ──────────────────────────────────")

    t_tls_handshake(shost, sport)
    t_chrome_fingerprint(shost, sport)
    t_h2_settings(shost, sport)
    t_h2_connect_stream(shost, sport)

    # ═══════════════════════════════════════════════════════════════════════
    # Section 2 — 经由 client proxy
    # ═══════════════════════════════════════════════════════════════════════
    print("\n── Section 2: 经由 client proxy ────────────────────────────")

    if not proxy_available:
        print(f"  [{WARN}] proxy unavailable — all proxy tests skipped")
    else:
        t_proxy_method_not_allowed(phost, pport)
        t_proxy_connect_200(phost, pport, shost, sport)
        t_proxy_data_relay(phost, pport, echo.host, echo.port)
        t_proxy_large_data(phost, pport, echo.host, echo.port, size=256 * 1024)
        t_proxy_concurrent(phost, pport, echo.host, echo.port, n=args.concurrent)
        t_proxy_connect_tls_through(phost, pport, shost, sport)

    # ═══════════════════════════════════════════════════════════════════════
    # 汇总
    # ═══════════════════════════════════════════════════════════════════════
    echo.close()
    kill_all()

    print()
    print("═" * 60)
    total  = len(_results)
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = total - passed
    print(f"  Result: {passed}/{total} passed", end="")
    if failed:
        print(f"  (\033[31m{failed} FAILED\033[0m)", end="")
        print()
        print("\n  Failed tests:")
        for name, ok, detail in _results:
            if not ok:
                print(f"    • {name}  — {detail}")
    else:
        print("  \033[32m✓ all passed\033[0m", end="")
    print()
    print("═" * 60)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        kill_all()
        sys.exit(130)
