"""服务指纹识别 — 用正则规则匹配 ProbeResult，识别服务厂商/产品/版本

流水线位置：probe_sender → ProbeResult → fingerprinter → ServiceInfo

匹配策略：
  - 对每个 ProbeResult，按 probe_type 取对应规则组，逐条尝试
  - tls_https_get 的规则池 = tls_https_get 自身规则 + http_get 规则（回退）
  - 取置信度最高的匹配；无匹配则生成低保真度 fallback
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from models import ProbeResult, ServiceInfo

_RULES_FILE = Path(__file__).parent.parent / "data" / "service_probes.json"
with open(_RULES_FILE, "r", encoding="utf-8") as f:
    _PROBE_RULES: Dict[str, List[dict]] = json.load(f)["rules"]


def _match_rule(rule: dict, result: ProbeResult) -> Optional[Tuple[str, float]]:
    """用一条规则匹配 ProbeResult，成功返回 (version, confidence)，失败返回 None

    匹配对象由规则字段决定：
      - 有 "header" → 从 HTTP 响应头中取值
      - 有 "subject_cn" → 从 TLS 证书 subject 中取 CommonName
      - 都没有 → 匹配 banner 原始文本
    """
    target: Optional[str] = None

    if rule.get("header"):
        target = result.headers.get(rule["header"].lower())
    elif rule.get("subject_cn"):
        subject = result.tls_info.get("subject", {})
        target = subject.get("commonName") or subject.get("CN")
    else:
        target = result.banner

    if not target:
        return None

    pattern = rule.get("regex")
    if not pattern:
        return None

    flags = re.IGNORECASE
    if rule.get("dotall"):
        flags |= re.DOTALL
    m = re.search(pattern, target, flags)
    if not m:
        return None

    version: Optional[str] = None
    if m.lastindex and m.lastindex >= 1:
        version = m.group(1)

    confidence = rule.get("confidence", 0.5)
    return (version, confidence)


def _fingerprint_probe_result(result: ProbeResult) -> ServiceInfo:
    """对单个 ProbeResult 执行指纹识别，返回 ServiceInfo

    规则匹配路径：
      1. 先从 probe_type 对应规则组中匹配
      2. 如果是 tls_https_get，额外回退到 http_get 规则组
      3. 取置信度最高的一条
      4. 无命中则构建 fallback ServiceInfo
    """
    rule_groups: List[List[dict]] = [_PROBE_RULES.get(result.probe_type, [])]
    if result.probe_type == "tls_https_get":
        rule_groups.append(_PROBE_RULES.get("http_get", []))

    best_rule: Optional[dict] = None
    best_version: Optional[str] = None
    best_confidence: float = -1.0

    for group in rule_groups:
        for rule in group:
            m = _match_rule(rule, result)
            if m:
                version, confidence = m
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_version = version
                    best_rule = rule

    if best_rule is not None:
        evidence = (result.banner or "")[:500]
        return ServiceInfo(
            host=result.host,
            port=result.port,
            protocol=best_rule.get("protocol", "unknown"),
            service_name=best_rule.get("name"),
            vendor=best_rule.get("vendor"),
            product=best_rule.get("product"),
            version=best_version,
            evidence=evidence,
            probe_type=result.probe_type,
            confidence=best_confidence,
            raw_banner=result.banner,
        )

    return _fallback_service(result)


def _fallback_service(result: ProbeResult) -> ServiceInfo:
    """构建低保真度 fallback ServiceInfo，保留原始 banner 供报告中展示"""
    if result.error:
        return ServiceInfo(
            host=result.host,
            port=result.port,
            protocol="unknown",
            confidence=0.0,
            probe_type=result.probe_type,
            raw_banner=result.banner,
        )

    if result.probe_type in ("http_get", "tls_https_get"):
        protocol = "https" if result.probe_type == "tls_https_get" else "http"
        return ServiceInfo(
            host=result.host,
            port=result.port,
            protocol=protocol,
            service_name="HTTP Server",
            confidence=0.2,
            evidence=(result.banner or "")[:500],
            probe_type=result.probe_type,
            raw_banner=result.banner,
        )

    return ServiceInfo(
        host=result.host,
        port=result.port,
        protocol="unknown",
        service_name="Unknown Service",
        confidence=0.1,
        evidence=(result.banner or "")[:500],
        probe_type=result.probe_type,
        raw_banner=result.banner,
    )


def fingerprint_host(probe_results: List[ProbeResult]) -> List[ServiceInfo]:
    """对一台主机的所有探测结果执行指纹识别

    Args:
        probe_results: probe_host() 产出的探测结果列表

    Returns:
        每个端口的服务识别结果列表，顺序与输入一致
    """
    return [_fingerprint_probe_result(r) for r in probe_results]


def fingerprint(all_probe_results: List[List[ProbeResult]]) -> List[List[ServiceInfo]]:
    """指纹识别主入口 — 对多台主机的探测结果批量处理"""

    return [fingerprint_host(host_results) for host_results in all_probe_results]
