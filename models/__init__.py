"""Sentinel 数据模型 — 所有模块间传递的数据结构定义"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional


class PortStatus(Enum):
    """端口扫描结果状态"""
    OPEN = auto()
    CLOSED = auto()
    FILTERED = auto()
    ERROR = auto()


@dataclass
class PortInfo:
    """单个端口的扫描结果"""
    port: int
    status: PortStatus
    reason: str = ""
    rtt_ms: Optional[float] = None


# ── HostResult：port_scanner 产出 ──

@dataclass
class HostResult:
    """单台主机的端口扫描结果集合"""
    host: str
    status: str
    ports: List[PortInfo] = field(default_factory=list)


# ── ProbeResult：probe_sender 产出 ──

@dataclass
class ProbeResult:
    """单次协议探测的原始结果"""
    host: str
    port: int
    probe_type: str = ""
    banner: Optional[str] = None
    headers: dict = field(default_factory=dict)
    tls_info: dict = field(default_factory=dict)
    error: Optional[str] = None


# ── ServiceInfo：fingerprinter 产出 ──

@dataclass
class ServiceInfo:
    """单个端口上识别出的服务指纹信息"""
    host: str
    port: int
    protocol: str
    service_name: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    evidence: str = ""
    probe_type: str = ""
    confidence: float = 0.0
    raw_banner: Optional[str] = None


# ── Vulnerability：cve_matcher 产出 ──

@dataclass
class Vulnerability:
    """一条匹配到的 CVE 漏洞记录"""
    cve_id: str
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    description: str = ""
    matched_on: dict = field(default_factory=dict)
    confidence: float = 0.0
    references: List[str] = field(default_factory=list)


# ── ScanReport：html_reporter 消费的顶层报告结构 ──

@dataclass
class ScanReport:
    """一次完整扫描的汇总结果"""
    targets: List[str] = field(default_factory=list)
    start_time: str = ""
    duration_seconds: float = 0.0
    host_results: List[HostResult] = field(default_factory=list)
    services: List[List[ServiceInfo]] = field(default_factory=list)
    vulnerabilities: List[List[Vulnerability]] = field(default_factory=list)
