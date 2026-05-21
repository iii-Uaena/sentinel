"""HTML 报告生成器 — 使用 Jinja2 渲染 ScanReport 为单 HTML 文件

流水线终端：ScanReport → html_reporter → output/*.html
"""

import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader

from models import HostResult, PortInfo, PortStatus, ScanReport, ServiceInfo, Vulnerability

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)


def generate_report(report: ScanReport, output_path: Optional[Path] = None) -> str:
    """生成 HTML 报告，返回 HTML 字符串，同时写入 output_path（如果指定）

    Args:
        report: 扫描汇总结果
        output_path: 输出文件路径，为 None 时默认写入 output/report_<timestamp>.html

    Returns:
        完整的 HTML 报告字符串
    """
    template = _env.get_template("report.html")
    data = _prepare_data(report)
    html = template.render(report=report, **data)

    if output_path is None:
        output_dir = Path(__file__).parent.parent / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"report_{ts}.html"

    Path(output_path).write_text(html, encoding="utf-8")
    return html


def _prepare_data(report: ScanReport) -> Dict[str, Any]:
    """将 ScanReport 整理为模板可直接使用的数据"""
    total_open_ports = _count_open_ports(report.host_results)
    total_services = sum(len(svcs) for svcs in report.services)
    total_cves = sum(len(vulns) for vulns in report.vulnerabilities)
    cve_by_severity = _count_cve_severities(report.vulnerabilities)
    hosts_up = sum(1 for h in report.host_results if h.status == "up")
    hosts_down = len(report.host_results) - hosts_up

    hosts: List[Dict[str, Any]] = []
    for idx, host_result in enumerate(report.host_results):
        services = report.services[idx] if idx < len(report.services) else []
        vulns = report.vulnerabilities[idx] if idx < len(report.vulnerabilities) else []
        hosts.append(_shape_host(host_result, services, vulns))

    return {
        "total_open_ports": total_open_ports,
        "total_services": total_services,
        "total_cves": total_cves,
        "cve_by_severity": cve_by_severity,
        "hosts_up": hosts_up,
        "hosts_down": hosts_down,
        "hosts": hosts,
    }


def _count_open_ports(host_results: List[HostResult]) -> int:
    """统计所有主机中 OPEN 端口总数"""
    count = 0
    for h in host_results:
        count += sum(1 for p in h.ports if p.status == PortStatus.OPEN)
    return count


def _count_cve_severities(vulnerabilities: List[List[Vulnerability]]) -> Dict[str, int]:
    """统计各严重等级的 CVE 数量"""
    counts: Dict[str, int] = {}
    for host_vulns in vulnerabilities:
        for v in host_vulns:
            sev = v.severity or "UNKNOWN"
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def _shape_host(
    host_result: HostResult,
    services: List[ServiceInfo],
    vulns: List[Vulnerability],
) -> Dict[str, Any]:
    """合并单台主机的端口扫描、服务识别、CVE 匹配结果"""
    svc_map: Dict[int, ServiceInfo] = {s.port: s for s in services}

    ports: List[Dict[str, Any]] = []
    for p in host_result.ports:
        svc = svc_map.get(p.port)
        ports.append({
            "port": p.port,
            "status": p.status.name,
            "rtt_ms": p.rtt_ms,
            "reason": p.reason,
            "protocol": svc.protocol if svc else "-",
            "service_name": svc.service_name if svc else None,
            "vendor": svc.vendor if svc else None,
            "product": svc.product if svc else None,
            "version": svc.version if svc else None,
            "confidence": svc.confidence if svc else None,
            "evidence": svc.evidence if svc else "",
            "is_identified": svc is not None and svc.confidence >= 0.3,
        })

    return {
        "host": host_result.host,
        "status": host_result.status,
        "open_ports": sum(1 for p in host_result.ports if p.status == PortStatus.OPEN),
        "service_count": len(services),
        "cve_count": len(vulns),
        "ports": ports,
        "vulnerabilities": vulns,
    }
