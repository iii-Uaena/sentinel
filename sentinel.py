#!/usr/bin/env python3
"""Sentinel — 轻量级网络漏洞扫描器

用法示例：
  python sentinel.py -t 192.168.1.1 -p 22,80,443
  python sentinel.py -t 192.168.1.0/24 -p 1-1000
  python sentinel.py -t targets.txt -p top100
"""

import argparse
import asyncio
import ipaddress
import sys
import time
from pathlib import Path
from typing import List

from scanner.port_scanner import scan as port_scan
from scanner.probe_sender import probe_host
from scanner.fingerprinter import fingerprint_host
from scanner.cve_matcher import match_host
from report.html_reporter import generate_report
from models import PortStatus, ScanReport

_TOP100_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135,
    139, 143, 161, 389, 443, 445, 465, 514, 515, 587,
    636, 873, 993, 995, 1080, 1194, 1433, 1434, 1521, 1701,
    1723, 1812, 2049, 2082, 2083, 2181, 2375, 2376, 3000, 3128,
    3260, 3306, 3389, 4000, 4369, 4444, 4567, 4848, 5000, 5001,
    5060, 5353, 5432, 5555, 5672, 5900, 5938, 5984, 6000, 6379,
    6443, 6666, 7001, 7002, 7474, 8000, 8001, 8009, 8080, 8081,
    8083, 8443, 8888, 9000, 9001, 9090, 9200, 9300, 9999, 10000,
    11211, 15672, 27017, 27018, 27019, 28017, 50000, 50030, 50060, 50070,
    50075, 50090, 54321, 55556, 58080, 60010, 60030, 61616, 64000, 65535,
]


def parse_ports(ports_str: str) -> List[int]:
    """解析端口字符串，支持单个端口、逗号列表、范围、top100 关键词"""
    if ports_str.lower() == "top100":
        return sorted(_TOP100_PORTS)

    ports: set = set()
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            try:
                start, end = int(start_str.strip()), int(end_str.strip())
                ports.update(range(start, end + 1))
            except ValueError:
                sys.stderr.write(f"[!] 无效端口范围: {part}\n")
        else:
            try:
                ports.add(int(part))
            except ValueError:
                sys.stderr.write(f"[!] 无效端口号: {part}\n")
    return sorted(ports)


def resolve_targets(target_arg: str) -> List[str]:
    """解析目标参数：单 IP、CIDR 网段或 IP 列表文件路径"""
    path = Path(target_arg)
    if path.is_file():
        targets: List[str] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
        return targets

    if "/" in target_arg:
        try:
            network = ipaddress.ip_network(target_arg, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            pass

    return [target_arg]


async def run_scan(
    targets: List[str],
    ports: List[int],
    concurrency: int = 100,
    timeout: float = 2.0,
    retries: int = 1,
) -> ScanReport:
    """执行完整扫描流水线，返回 ScanReport"""
    start_time = time.time()
    start_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(start_time))

    # ── Phase 1: 端口扫描 ──
    sys.stderr.write(f"[*] 端口扫描: {len(targets)} 台主机, {len(ports)} 个端口, 并发 {concurrency}\n")
    host_results = await port_scan(targets, ports, concurrency, timeout, retries)
    open_hosts = [h for h in host_results if h.status == "up"]
    sys.stderr.write(f"[+] 端口扫描完成: {len(open_hosts)} up, {len(host_results) - len(open_hosts)} down\n")

    # ── Phase 2~4: 协议探测 → 指纹识别 → CVE 匹配 ──
    probe_map: dict = {}
    svc_map: dict = {}
    vuln_map: dict = {}

    for h in open_hosts:
        sys.stderr.write(f"    {h.host}: ")
        probes = await probe_host(h, timeout)
        probe_map[h.host] = probes
        id_count = sum(1 for r in probes if r.error is None)
        services = fingerprint_host(probes)
        svc_map[h.host] = services
        vulns = match_host(services)
        vuln_map[h.host] = vulns
        sys.stderr.write(f"{id_count}/{len(probes)} 探测, {len(services)} 服务, {len(vulns)} CVE\n")

    all_services = [svc_map.get(h.host, []) for h in host_results]
    all_vulns = [vuln_map.get(h.host, []) for h in host_results]

    # ── 汇总 ──
    duration = round(time.time() - start_time, 2)
    total_services = sum(len(s) for s in all_services)
    total_cves = sum(len(v) for v in all_vulns)
    sys.stderr.write(f"[+] 扫描完成: {total_services} 服务识别, {total_cves} CVE 命中, 耗时 {duration}s\n")

    return ScanReport(
        targets=targets,
        start_time=start_iso,
        duration_seconds=duration,
        host_results=host_results,
        services=all_services,
        vulnerabilities=all_vulns,
    )

def _print_scan_summary(report: ScanReport) -> None:
    """Print scan results table to stdout (nmap-like format)"""
    up_count = sum(1 for h in report.host_results if h.status == "up")
    down_count = len(report.host_results) - up_count

    total_open = sum(
        sum(1 for p in h.ports if p.status == PortStatus.OPEN)
        for h in report.host_results
    )
    total_services = sum(len(svcs) for svcs in report.services)
    total_cves = sum(len(vulns) for vulns in report.vulnerabilities)

    print()
    print("=" * 78)
    print(f"  Sentinel  —  {len(report.host_results)} host(s) scanned in {report.duration_seconds}s")
    print("=" * 78)

    for idx, host_result in enumerate(report.host_results):
        if host_result.status != "up":
            continue

        services = report.services[idx] if idx < len(report.services) else []
        vulns = report.vulnerabilities[idx] if idx < len(report.vulnerabilities) else []
        svc_map = {s.port: s for s in services}
        open_ports = [p for p in host_result.ports if p.status == PortStatus.OPEN]

        print(f"\n  {host_result.host:<60} [UP]")

        for p in open_ports:
            svc = svc_map.get(p.port)
            protocol = svc.protocol if svc and svc.protocol != "unknown" else "-"
            version = svc.version if svc and svc.version else ""
            version_str = f"  {version}" if version else ""
            print(f"    {str(p.port) + '/tcp':<9} {protocol:<22}{version_str}")

        if not open_ports:
            print(f"    (no open ports)")

        id_count = sum(1 for s in services if s.protocol != "unknown")
        if vulns:
            sev_counts: dict = {}
            for v in vulns:
                sev_counts[v.severity] = sev_counts.get(v.severity, 0) + 1
            sev_parts = ", ".join(f"{c} {s}" for s, c in sorted(sev_counts.items()))
            print(f"    {id_count} services  ·  {len(vulns)} CVEs ({sev_parts})")
        elif id_count > 0:
            print(f"    {id_count} services  ·  0 CVEs")

    print()
    print(f"  {up_count} hosts UP, {down_count} hosts DOWN")
    print(f"  {total_open} open ports, {total_services} services, {total_cves} CVEs")


def _report_link(path: Path) -> str:
    """Format the report path as a clickable file:// URL.

    Most modern terminals (Windows Terminal, iTerm2, GNOME Terminal, VS Code)
    auto-detect file:// URLs and make them Ctrl+Click clickable.
    """
    file_url = path.resolve().as_uri()
    return f"\n  Report: {file_url}\n"

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel — 轻量级网络漏洞扫描器",
    )
    parser.add_argument("-t", "--target", required=True,
                        help="目标 IP、CIDR 网段（如 192.168.1.0/24）或 IP 列表文件路径")
    parser.add_argument("-p", "--ports", default="top100",
                        help="端口列表，支持 22,80,443 或 1-1000 或混合，默认 top100")
    parser.add_argument("-o", "--output", default=None,
                        help="报告输出路径（默认 output/report_<timestamp>.html）")
    parser.add_argument("--concurrency", type=int, default=100,
                        help="最大并发 TCP 连接数（默认 100）")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="单连接超时秒数（默认 2.0）")
    parser.add_argument("--retries", type=int, default=1,
                        help="FILTERED/ERROR 状态重试次数（默认 1）")
    args = parser.parse_args()

    targets = resolve_targets(args.target)
    ports = parse_ports(args.ports)

    if not targets:
        sys.stderr.write("[!] 错误: 未解析到有效目标\n")
        sys.exit(1)
    if not ports:
        sys.stderr.write("[!] 错误: 未解析到有效端口\n")
        sys.exit(1)

    report = asyncio.run(run_scan(
        targets=targets,
        ports=ports,
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
    ))

    _print_scan_summary(report)

    # Determine output path before calling generate_report
    if args.output:
        output_path = Path(args.output)
    else:
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        output_path = Path(__file__).parent / "output" / f"report_{ts}.html"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    generate_report(report, output_path)
    print(_report_link(output_path))


if __name__ == "__main__":
    main()
