#!/usr/bin/env python3
"""
portscanner.py - a simple multithreaded TCP connect scanner.

Only scan systems you own or have explicit permission to test.
Safe practice target: scanme.nmap.org (allowed by the Nmap project, be polite).
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


def parse_ports(spec: str) -> list[int]:
    """Turn '22,80,443' or '1-1024' or '22,80,100-200' into a sorted list of ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Ports out of range (1-65535): {bad[:5]}")
    return sorted(ports)


def grab_banner(sock: socket.socket) -> str:
    """Try to read a short banner from an open port. Returns '' if none."""
    try:
        sock.settimeout(1.0)
        data = sock.recv(256)
        return data.decode(errors="ignore").strip().splitlines()[0][:80]
    except (socket.timeout, OSError, IndexError):
        return ""


def scan_port(host: str, port: int, timeout: float) -> dict | None:
    """Attempt a TCP connection. Return info dict if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) != 0:
                return None
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            return {"port": port, "service": service, "banner": grab_banner(s)}
    except OSError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple multithreaded TCP port scanner")
    parser.add_argument("target", help="hostname or IP address to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="ports to scan, e.g. 22,80,443 or 1-1024 (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="number of worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="connection timeout in seconds (default: 0.5)")
    parser.add_argument("-o", "--output", help="save results to this text file")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
        ports = parse_ports(args.ports)
    except socket.gaierror:
        print(f"Could not resolve host: {args.target}")
        return 1
    except ValueError as e:
        print(f"Invalid port specification: {e}")
        return 1

    print(f"Scanning {args.target} ({ip}) - {len(ports)} ports")
    print(f"Started: {datetime.now():%Y-%m-%d %H:%M:%S}\n")

    results = []
    start = time.time()
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = [pool.submit(scan_port, ip, p, args.timeout) for p in ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    banner = f"  | {result['banner']}" if result["banner"] else ""
                    print(f"[OPEN] {result['port']:<6} {result['service']}{banner}")
    except KeyboardInterrupt:
        print("\nScan interrupted.")

    results.sort(key=lambda r: r["port"])
    elapsed = time.time() - start
    print(f"\nDone. {len(results)} open port(s) found in {elapsed:.2f}s")

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"Scan of {args.target} ({ip}) at {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            for r in results:
                f.write(f"{r['port']}\t{r['service']}\t{r['banner']}\n")
        print(f"Results saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
