#!/usr/bin/env python3
"""CLI mode for CCTV Cam Scanner Radar."""

import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner import scan_host, get_default_private_cidr

BANNER = r"""
=========================================================
 CCTV CAM SCANNER RADAR
 Coded by Cyber Security Engineer Mr Sabaz Ali Khan
 Authorized private-network discovery only
=========================================================
"""

def allowed_network(raw):
    net = ipaddress.ip_network(raw, strict=False)
    if net.version != 4:
        raise ValueError("IPv4 only.")
    if not (net.is_private or net.is_loopback or net.is_link_local):
        raise ValueError("Public ranges are blocked.")
    if net.num_addresses > 1024:
        raise ValueError("Maximum range is /22 (1024 addresses).")
    return net

def main():
    parser = argparse.ArgumentParser(description="Authorized CCTV/IP-camera LAN discovery scanner")
    parser.add_argument("cidr", nargs="?", default=get_default_private_cidr(),
                        help="Private IPv4 CIDR, e.g. 192.168.1.0/24")
    parser.add_argument("--timeout", type=float, default=0.35)
    parser.add_argument("--workers", type=int, default=48)
    args = parser.parse_args()

    print(BANNER)
    net = allowed_network(args.cidr)
    timeout = max(0.1, min(args.timeout, 3.0))
    workers = max(4, min(args.workers, 64))
    ips = [str(ip) for ip in net.hosts()]

    print(f"[+] Scanning {net} ({len(ips)} host addresses)")
    print("[+] No password guessing, exploits, or stream access are performed.\n")

    found = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_host, ip, timeout): ip for ip in ips}
        for future in as_completed(futures):
            r = future.result()
            if r["open_ports"]:
                mark = "[CAM?]" if r["possible_camera"] else "[DEV ]"
                ports = ",".join(map(str, r["open_ports"]))
                print(f"{mark} {r['ip']:<15} ports={ports:<24} {r['assessment']}")
                if r["possible_camera"]:
                    found += 1

    print(f"\n[+] Finished. Possible camera/NVR devices: {found}")

if __name__ == "__main__":
    main()
