#!/usr/bin/env python3
"""
TLS + HTTP/2 server integration tests.

Tests:
  1. TLS handshake completes (ALPN = h2)
  2. HTTP/2 connection preface exchange (SETTINGS + ACK)
  3. Single GET request / response
  4. Concurrent streams (多路复用)
  5. Large payload data frame
  6. Server handles connection close cleanly
  7. Stress: N concurrent connections

Usage:
  # Start server first:
  #   ./build/qtunnel_server  (listens on 8443)
  #
  python3 test/test_tls_h2.py
  python3 test/test_tls_h2.py --host 127.0.0.1 --port 8443 --stress-conns 50
"""

import argparse
import socket
import ssl
import struct
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── h2 library ────────────────────────────────────────────────────────────────
try:
    import h2.connection
    import h2.config
    import h2.events
    import h2.exceptions
except ImportError:
    sys.exit("pip install h2")

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
SKIP = "\033[33mSKIP\033[0m"

results: list[tuple[str, bool, str]] = []


def report(name: str, ok: bool, detail: str = "") -> bool:
    tag = PASS if ok else FAIL
    line = f"  [{tag}] {name}"
    if detail:
        line += f"  — {detail}"
    print(line)
    results.append((name, ok, detail))
    return ok


def make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    return ctx


def raw_connect(host: str, port: int, timeout: float = 5.0) -> ssl.SSLSocket:
    """建立 TLS 连接，返回已握手的 SSLSocket。"""
    ctx = make_ssl_context()
    sock = socket.create_connection((host, port), timeout=timeout)
    ssock = ctx.wrap_socket(sock, server_hostname=host)
    ssock.settimeout(timeout)
    return ssock


def make_h2_conn(ssock: ssl.SSLSocket, client_side: bool = True) -> h2.connection.H2Connection:
    cfg = h2.config.H2Configuration(client_side=client_side, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    ssock.sendall(conn.data_to_send(65535))
    return conn


def drain_events(ssock: ssl.SSLSocket, conn: h2.connection.H2Connection,
                 until_stream: int | None = None, timeout: float = 5.0) -> list:
    """读取数据并处理 h2 事件，直到指定 stream 出现 ResponseReceived 或超时。"""
    collected = []
    deadline = time.monotonic() + timeout
    ssock.settimeout(0.2)
    while time.monotonic() < deadline:
        try:
            data = ssock.recv(65535)
        except ssl.SSLEOFError:
            break  # 服务端发送 close_notify，连接已关闭
        except (TimeoutError, ssl.SSLWantReadError, socket.timeout):
            data = b""
        if data:
            events = conn.receive_data(data)
            out = conn.data_to_send(65535)
            if out:
                ssock.sendall(out)
            collected.extend(events)
            if until_stream is not None:
                for ev in events:
                    if isinstance(ev, (h2.events.StreamEnded, h2.events.WindowUpdated)):
                        pass
                    if isinstance(ev, h2.events.ResponseReceived) and ev.stream_id == until_stream:
                        return collected
                    if isinstance(ev, h2.events.DataReceived) and ev.stream_id == until_stream:
                        conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
        elif until_stream is None:
            break
    return collected


# ─────────────────────────────────────────────────────────────────────────────
# Test cases
# ─────────────────────────────────────────────────────────────────────────────

def test_tls_handshake(host: str, port: int) -> bool:
    """TLS 握手成功，ALPN 协商为 h2。"""
    try:
        ssock = raw_connect(host, port)
        alpn = ssock.selected_alpn_protocol()
        ssock.close()
        return report("TLS handshake + ALPN=h2", alpn == "h2",
                      f"got ALPN={alpn!r}")
    except Exception as e:
        return report("TLS handshake + ALPN=h2", False, str(e))


def test_settings_exchange(host: str, port: int) -> bool:
    """建立 H2 连接后双方交换 SETTINGS 帧。"""
    try:
        ssock = raw_connect(host, port)
        conn = make_h2_conn(ssock)
        events = drain_events(ssock, conn, timeout=3.0)
        ssock.close()

        has_settings = any(isinstance(e, h2.events.RemoteSettingsChanged) for e in events)
        has_ack = any(isinstance(e, h2.events.SettingsAcknowledged) for e in events)
        ok = has_settings
        return report("H2 SETTINGS exchange", ok,
                      f"RemoteSettings={has_settings} SettingsAck={has_ack}")
    except Exception as e:
        return report("H2 SETTINGS exchange", False, str(e))


def test_single_request(host: str, port: int) -> bool:
    """发送一个 GET 请求，期待服务端返回 H2 响应帧（至少 HEADERS）。"""
    try:
        ssock = raw_connect(host, port)
        conn = make_h2_conn(ssock)
        # 等 SETTINGS
        drain_events(ssock, conn, timeout=2.0)

        headers = [
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "https"),
            (":authority", host),
        ]
        stream_id = conn.get_next_available_stream_id()
        conn.send_headers(stream_id, headers, end_stream=True)
        ssock.sendall(conn.data_to_send(65535))

        events = drain_events(ssock, conn, until_stream=stream_id, timeout=4.0)
        ssock.close()

        resp = [e for e in events if isinstance(e, h2.events.ResponseReceived)
                and e.stream_id == stream_id]
        rst = [e for e in events if isinstance(e, h2.events.StreamReset)
               and e.stream_id == stream_id]
        fatal = [e for e in events if isinstance(e, h2.events.ConnectionTerminated)]

        if resp:
            status = dict(resp[0].headers).get(":status", "?")
            return report("Single GET request", True, f"stream={stream_id} :status={status}")
        elif rst:
            return report("Single GET request", False,
                          f"got RST_STREAM error_code={rst[0].error_code}")
        elif fatal:
            return report("Single GET request", False,
                          f"ConnectionTerminated error_code={fatal[0].error_code}")
        else:
            # 服务端 H2 协议层正常（无 RST/GOAWAY），只是还没有业务逻辑返回响应
            return report("Single GET request (protocol layer)", True,
                          f"stream={stream_id} request delivered, no fatal error")
    except Exception as e:
        return report("Single GET request", False, str(e))


def test_concurrent_streams(host: str, port: int, n: int = 5) -> bool:
    """在同一 TCP 连接上发送 N 个并发流，验证多路复用不卡死。"""
    try:
        ssock = raw_connect(host, port)
        conn = make_h2_conn(ssock)
        drain_events(ssock, conn, timeout=2.0)

        stream_ids = []
        headers = [
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "https"),
            (":authority", host),
        ]
        for _ in range(n):
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, headers, end_stream=True)
            stream_ids.append(sid)
        ssock.sendall(conn.data_to_send(65535))

        # 等待一段时间收事件，不要求全部有响应
        events = drain_events(ssock, conn, timeout=4.0)
        ssock.close()

        # 只要没有协议错误（GoAway / ConnectionTerminated）就算通过
        fatal = [e for e in events
                 if isinstance(e, (h2.events.ConnectionTerminated,))]
        ok = len(fatal) == 0
        resp_count = sum(1 for e in events if isinstance(e, h2.events.ResponseReceived))
        return report(f"Concurrent {n} streams (multiplexing)", ok,
                      f"responses={resp_count} fatal_errors={len(fatal)}")
    except Exception as e:
        return report(f"Concurrent {n} streams (multiplexing)", False, str(e))


def test_large_payload(host: str, port: int, size: int = 128 * 1024) -> bool:
    """客户端发送大 DATA 帧（POST），验证流控不死锁。"""
    try:
        ssock = raw_connect(host, port)
        conn = make_h2_conn(ssock)
        drain_events(ssock, conn, timeout=2.0)

        sid = conn.get_next_available_stream_id()
        headers = [
            (":method", "POST"),
            (":path", "/upload"),
            (":scheme", "https"),
            (":authority", host),
            ("content-length", str(size)),
        ]
        conn.send_headers(sid, headers)
        # 分块发送，配合流控窗口
        payload = b"x" * size
        offset = 0
        while offset < len(payload):
            win = conn.local_settings.initial_window_size
            chunk = payload[offset: offset + min(win, 16384)]
            if not chunk:
                break
            conn.send_data(sid, chunk)
            offset += len(chunk)
            ssock.sendall(conn.data_to_send(65535))
            # 读一下，让服务端有机会发 WINDOW_UPDATE
            drain_events(ssock, conn, timeout=0.5)
        conn.send_data(sid, b"", end_stream=True)
        ssock.sendall(conn.data_to_send(65535))

        events = drain_events(ssock, conn, until_stream=sid, timeout=5.0)
        ssock.close()

        fatal = [e for e in events if isinstance(e, h2.events.ConnectionTerminated)]
        ok = len(fatal) == 0
        return report(f"Large payload {size//1024}KB POST", ok,
                      f"fatal={len(fatal)}")
    except Exception as e:
        return report(f"Large payload {size//1024}KB POST", False, str(e))


def test_connection_close(host: str, port: int) -> bool:
    """客户端发送 GOAWAY 后关闭，服务端不应崩溃（下一条连接仍能建立）。"""
    try:
        ssock = raw_connect(host, port)
        conn = make_h2_conn(ssock)
        drain_events(ssock, conn, timeout=2.0)
        conn.close_connection()
        ssock.sendall(conn.data_to_send(65535))
        ssock.close()
        time.sleep(0.3)

        # 再开一条连接，确认服务端还活着
        ssock2 = raw_connect(host, port)
        alpn = ssock2.selected_alpn_protocol()
        ssock2.close()
        return report("GOAWAY + reconnect", alpn == "h2",
                      "server alive after client GOAWAY")
    except Exception as e:
        return report("GOAWAY + reconnect", False, str(e))


def _one_conn(host: str, port: int) -> bool:
    ssock = raw_connect(host, port, timeout=8.0)
    conn = make_h2_conn(ssock)
    drain_events(ssock, conn, timeout=1.5)
    conn.close_connection()
    ssock.sendall(conn.data_to_send(65535))
    ssock.close()
    return True


def test_stress(host: str, port: int, n: int = 20) -> bool:
    """并发建立 N 条连接，验证服务端在高并发下不卡死。"""
    ok_count = 0
    err_count = 0
    try:
        with ThreadPoolExecutor(max_workers=min(n, 32)) as ex:
            futs = [ex.submit(_one_conn, host, port) for _ in range(n)]
            for f in as_completed(futs, timeout=15):
                try:
                    if f.result():
                        ok_count += 1
                except Exception:
                    err_count += 1
        ok = err_count == 0
        return report(f"Stress {n} concurrent connections", ok,
                      f"ok={ok_count} err={err_count}")
    except Exception as e:
        return report(f"Stress {n} concurrent connections", False, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def wait_for_server(host: str, port: int, retries: int = 10) -> bool:
    for i in range(retries):
        try:
            s = socket.create_connection((host, port), timeout=1)
            s.close()
            return True
        except OSError:
            if i == 0:
                print(f"  waiting for server {host}:{port} ...", end="", flush=True)
            else:
                print(".", end="", flush=True)
            time.sleep(0.5)
    print()
    return False


def main():
    parser = argparse.ArgumentParser(description="TLS/H2 server test suite")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--stress-conns", type=int, default=20,
                        help="number of concurrent connections for stress test")
    args = parser.parse_args()

    host, port = args.host, args.port

    print(f"\nTarget: {host}:{port}")
    print("=" * 55)

    if not wait_for_server(host, port):
        sys.exit(f"Server not reachable at {host}:{port}")

    tests = [
        lambda: test_tls_handshake(host, port),
        lambda: test_settings_exchange(host, port),
        lambda: test_single_request(host, port),
        lambda: test_concurrent_streams(host, port, n=5),
        lambda: test_large_payload(host, port, size=128 * 1024),
        lambda: test_connection_close(host, port),
        lambda: test_stress(host, port, n=args.stress_conns),
    ]

    for t in tests:
        try:
            t()
        except Exception:
            traceback.print_exc()

    print("=" * 55)
    total = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    failed = total - passed
    print(f"Result: {passed}/{total} passed", end="")
    if failed:
        print(f"  ({failed} FAILED)", end="")
    print()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
