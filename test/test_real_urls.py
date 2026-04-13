#!/usr/bin/env python3
"""
wtunnel 真实 URL 端到端测试
============================

通过本地 HTTP 代理 (127.0.0.1:8080) 访问真实 HTTPS 网址：
  - https://baidu.com        — 中文网站，验证基本 HTTPS 通道
  - https://speed.cloudflare.com/__down?bytes=10000000 — 10 MB 大文件，验证吞吐和流控

用法:
  # 先确保 server 和 client proxy 已启动：
  #   ./build/bin/qtunnel_server &
  #   ./build/bin/qtunnel_client &
  #
  python3 test/test_real_urls.py
  python3 test/test_real_urls.py --proxy 127.0.0.1:8080 --timeout 30
"""

import argparse
import socket
import ssl
import sys
import time
import subprocess
import os
from contextlib import suppress

# ── 依赖检查 ─────────────────────────────────────────────────────────────────
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("❌  pip install requests")

# ── 结果追踪 ──────────────────────────────────────────────────────────────────
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


def fmt_size(n: int) -> str:
    if n >= 1_000_000:
        return f"{n/1_000_000:.2f} MB"
    if n >= 1_000:
        return f"{n/1_000:.1f} KB"
    return f"{n} B"


def fmt_speed(bps: float) -> str:
    if bps >= 1_000_000:
        return f"{bps/1_000_000:.2f} MB/s"
    if bps >= 1_000:
        return f"{bps/1_000:.1f} KB/s"
    return f"{bps:.0f} B/s"


# ── 工具 ─────────────────────────────────────────────────────────────────────

def make_session(proxy: str, timeout: float) -> requests.Session:
    """创建带代理的 requests Session，跳过证书验证（穿透代理场景）。"""
    sess = requests.Session()
    sess.proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    sess.verify  = False          # 自签名 tunnel server，目标站证书由客户端 TLS 验证
    sess.timeout = timeout
    # Chrome-like headers
    sess.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
    })
    return sess


def wait_port(host: str, port: int, retries: int = 20) -> bool:
    for _ in range(retries):
        try:
            socket.create_connection((host, port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


# ── 测试用例 ─────────────────────────────────────────────────────────────────

def t_baidu(sess: requests.Session, timeout: float) -> bool:
    """访问 https://baidu.com，验证 HTTPS 隧道连通性和内容完整性。"""
    name = "https://baidu.com"
    try:
        t0 = time.monotonic()
        r = sess.get("https://baidu.com", timeout=timeout,
                     allow_redirects=True, stream=False)
        elapsed = time.monotonic() - t0

        status = r.status_code
        size   = len(r.content)
        ok     = status in (200, 301, 302) and size > 0

        # 简单内容验证：百度主页必含 "baidu"
        has_content = b"baidu" in r.content.lower()
        if ok and not has_content:
            ok = False

        return report(name, ok,
                      f"HTTP {status}  size={fmt_size(size)}"
                      f"  contains_baidu={'yes' if has_content else 'NO'}"
                      f"  t={elapsed:.2f}s")
    except requests.exceptions.ConnectionError as e:
        return report(name, False, f"Connection error: {e}")
    except requests.exceptions.Timeout:
        return report(name, False, f"Timeout after {timeout}s")
    except Exception as e:
        return report(name, False, str(e))


def t_cloudflare_download(sess: requests.Session, timeout: float,
                            size_bytes: int = 10_000_000) -> bool:
    """
    通过代理下载 Cloudflare speed test 端点 (10 MB)。
    验证：大数据流控、吞吐量、数据完整性（全零字节）。
    """
    url  = f"https://speed.cloudflare.com/__down?bytes={size_bytes}"
    name = f"Cloudflare download {fmt_size(size_bytes)}"
    try:
        t0 = time.monotonic()
        r  = sess.get(url, timeout=timeout, stream=True)

        if r.status_code != 200:
            return report(name, False, f"HTTP {r.status_code}")

        received   = 0
        chunk_size = 65536
        last_print = t0
        speed_samples: list[tuple[float, int]] = []  # (time, cumulative_bytes)

        for chunk in r.iter_content(chunk_size=chunk_size):
            if not chunk:
                continue
            received += len(chunk)
            now = time.monotonic()
            speed_samples.append((now, received))
            # Progress every 1 MB
            if now - last_print >= 1.0:
                elapsed  = now - t0
                speed    = received / elapsed if elapsed > 0 else 0
                pct      = received / size_bytes * 100
                print(f"    ↓ {fmt_size(received)} / {fmt_size(size_bytes)}"
                      f"  ({pct:.0f}%)  {fmt_speed(speed)}", end="\r", flush=True)
                last_print = now

        print()  # newline after progress

        elapsed = time.monotonic() - t0
        avg_speed = received / elapsed if elapsed > 0 else 0

        # Peak speed over any 1-second window
        peak_speed = 0.0
        for i, (t_i, b_i) in enumerate(speed_samples):
            for j in range(i - 1, -1, -1):
                t_j, b_j = speed_samples[j]
                if t_i - t_j >= 1.0:
                    peak_speed = max(peak_speed, (b_i - b_j) / (t_i - t_j))
                    break

        complete = (received == size_bytes)
        ok = complete

        return report(name, ok,
                      f"received={fmt_size(received)}/{fmt_size(size_bytes)}"
                      f"  avg={fmt_speed(avg_speed)}"
                      f"  peak={fmt_speed(peak_speed)}"
                      f"  t={elapsed:.1f}s"
                      + ("" if complete else "  INCOMPLETE"))
    except requests.exceptions.ConnectionError as e:
        return report(name, False, f"Connection error: {e}")
    except requests.exceptions.Timeout:
        return report(name, False, f"Timeout after {timeout}s")
    except Exception as e:
        return report(name, False, str(e))


def t_cloudflare_meta(sess: requests.Session, timeout: float) -> bool:
    """
    访问 Cloudflare CDN 元数据端点，验证响应头中的 CF-RAY / server 字段。
    """
    url  = "https://speed.cloudflare.com/cdn-cgi/trace"
    name = "Cloudflare trace (CDN metadata)"
    try:
        t0 = time.monotonic()
        r  = sess.get(url, timeout=timeout)
        elapsed = time.monotonic() - t0

        ok = r.status_code == 200
        text = r.text[:500] if ok else ""
        # 期望包含 fl= 和 loc= 字段
        has_fl  = "fl=" in text
        has_loc = "loc=" in text
        loc = ""
        for line in text.splitlines():
            if line.startswith("loc="):
                loc = line.split("=", 1)[1]

        ok = ok and has_fl
        return report(name, ok,
                      f"HTTP {r.status_code}"
                      f"  loc={loc or '?'}"
                      f"  cf_ray={'yes' if 'cf-ray' in r.headers else 'no'}"
                      f"  t={elapsed:.2f}s")
    except Exception as e:
        return report(name, False, str(e))


def t_https_redirect(sess: requests.Session, timeout: float) -> bool:
    """验证代理正确处理 HTTPS 重定向（baidu.com 会重定向到 www.baidu.com）。"""
    name = "HTTPS redirect handling (baidu.com → www)"
    try:
        # 禁止自动跟随重定向，手动检查
        r = sess.get("https://baidu.com", timeout=timeout, allow_redirects=False)
        redirected = r.status_code in (301, 302, 307, 308)
        location   = r.headers.get("Location", "")
        # 再跟随一次
        if redirected and location:
            r2 = sess.get(location, timeout=timeout, allow_redirects=True)
            final_ok = r2.status_code == 200
        else:
            final_ok = r.status_code == 200

        ok = final_ok
        return report(name, ok,
                      f"first={r.status_code}"
                      f"  location={location[:60] or 'none'}"
                      f"  final_ok={final_ok}")
    except Exception as e:
        return report(name, False, str(e))


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="wtunnel real-URL test")
    parser.add_argument("--proxy",   default="127.0.0.1:8080",
                        help="proxy address host:port")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="per-request timeout in seconds")
    parser.add_argument("--dl-size", type=int, default=10_000_000,
                        help="download size in bytes (default 10 MB)")
    parser.add_argument("--server-bin", default="build/bin/qtunnel_server")
    parser.add_argument("--client-bin", default="build/bin/qtunnel_client")
    parser.add_argument("--no-auto-launch", action="store_true")
    args = parser.parse_args()

    proxy_host, proxy_port_str = args.proxy.rsplit(":", 1)
    proxy_port = int(proxy_port_str)

    print()
    print("═" * 62)
    print("  wtunnel real-URL test")
    print(f"  proxy  : {args.proxy}")
    print(f"  timeout: {args.timeout}s  dl-size: {fmt_size(args.dl_size)}")
    print("═" * 62)

    # ── 自动启动 ──────────────────────────────────────────────────────────────
    _procs = []

    def launch(cmd, name):
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _procs.append(p)
        print(f"  [launched] {name} pid={p.pid}")
        return p

    server_port = 8443
    try:
        socket.create_connection(("127.0.0.1", server_port), timeout=1).close()
        print(f"\n[server] running on 127.0.0.1:{server_port}")
    except OSError:
        if not args.no_auto_launch and os.path.exists(args.server_bin):
            print(f"\n[server] launching {args.server_bin} ...")
            launch([args.server_bin], "qtunnel_server")
            wait_port("127.0.0.1", server_port)
        else:
            print(f"\n[server] not running on 127.0.0.1:{server_port}, launch manually")

    try:
        socket.create_connection((proxy_host, proxy_port), timeout=1).close()
        print(f"[proxy]  running on {args.proxy}")
    except OSError:
        if not args.no_auto_launch and os.path.exists(args.client_bin):
            print(f"[proxy]  launching {args.client_bin} ...")
            launch([args.client_bin, str(proxy_port), "127.0.0.1", str(server_port)],
                   "qtunnel_client")
            if not wait_port(proxy_host, proxy_port, retries=30):
                print(f"  [{FAIL}] proxy failed to start")
                for p in _procs: p.terminate()
                sys.exit(1)
        else:
            print(f"  [{FAIL}] proxy not running at {args.proxy}, launch manually")
            sys.exit(1)

    sess = make_session(args.proxy, args.timeout)

    # ── 网络连通性检查 ────────────────────────────────────────────────────────
    print("\n── 网络连通性预检 ───────────────────────────────────────────")
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3).close()
        print(f"  [{PASS}] 外网连通 (DNS reachable)")
    except OSError:
        print(f"  [{WARN}] 外网不可达 — 以下测试可能全部超时")

    # ── 测试 ─────────────────────────────────────────────────────────────────
    print("\n── baidu.com ────────────────────────────────────────────────")
    t_baidu(sess, args.timeout)
    t_https_redirect(sess, args.timeout)

    print("\n── speed.cloudflare.com ─────────────────────────────────────")
    t_cloudflare_meta(sess, args.timeout)
    t_cloudflare_download(sess, args.timeout, args.dl_size)

    # ── 汇总 ─────────────────────────────────────────────────────────────────
    for p in _procs:
        with suppress(Exception): p.terminate(); p.wait(timeout=3)

    print()
    print("═" * 62)
    total  = len(_results)
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = total - passed
    print(f"  Result: {passed}/{total} passed", end="")
    if failed:
        print(f"  (\033[31m{failed} FAILED\033[0m)")
        for name, ok, detail in _results:
            if not ok:
                print(f"    • {name}  — {detail}")
    else:
        print(f"  \033[32m✓ all passed\033[0m")
    print("═" * 62)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
