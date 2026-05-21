"""CVE 漏洞匹配 — 根据 ServiceInfo 的 vendor/product/version 匹配本地 CVE 库

流水线位置：fingerprinter → ServiceInfo → cve_matcher → Vulnerability

匹配规则：
  1. vendor + product 精确匹配（忽略大小写）
  2. 有 version 时检查 version_range（区间比较）
  3. 无 version 时仍匹配但置信度降低
  4. version_range 支持：* / <=x.y.z / <x.y.z / >=a,<=b 等格式
"""

import csv
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from models import ServiceInfo, Vulnerability

_CVE_DATA_DIR = Path(__file__).parent.parent / "data"

# CSV 列名别名映射（不区分大小写）→ 统一字段名
_CSV_COLUMN_ALIASES: Dict[str, str] = {
    "vendor": "vendor",
    "product": "product",
    "version_range": "version_range",
    "affected_version": "version_range",
    "version": "version_range",
    "cve_id": "id",
    "cve": "id",
    "cve-id": "id",
    "name": "id",
    "severity": "severity",
    "risk": "severity",
    "level": "severity",
    "cvss_score": "cvss_score",
    "cvss": "cvss_score",
    "score": "cvss_score",
    "description": "description",
    "summary": "description",
    "title": "description",
    "desc": "description",
    "references": "references",
    "reference": "references",
    "url": "references",
    "link": "references",
}


def _load_builtin_cves() -> List[dict]:
    """从 data/cve_db.json 加载内置 CVE 库"""
    cve_file = _CVE_DATA_DIR / "cve_db.json"
    if not cve_file.is_file():
        return []
    with open(cve_file, "r", encoding="utf-8") as f:
        return json.load(f).get("cves", [])


def _load_custom_csvs() -> List[dict]:
    """扫描 data/cve/custom/ 下所有 .csv 文件，解析后归一化返回

    表头匹配策略：
      - 读取首行作为列名
      - 列名去空格、转小写后查 _CSV_COLUMN_ALIASES 得到统一字段名
      - 无 alias 匹配的列直接丢弃
      - 缺失 vendor/product/id 任何一项的行跳过
    """
    custom_dir = _CVE_DATA_DIR / "cve" / "custom"
    if not custom_dir.is_dir():
        return []

    records: List[dict] = []
    for csv_file in sorted(custom_dir.glob("*.csv")):
        try:
            with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
                _parse_csv(f, records, csv_file.name)
        except Exception:
            pass

    return records


def _parse_csv(f, records: List[dict], filename: str) -> None:
    """解析单个 CSV 文件，追加到 records"""
    lines = [line for line in f if line.strip() and not line.strip().startswith("#")]
    if not lines:
        return

    reader = csv.reader(lines)
    raw_header = next(reader, None)
    if raw_header is None:
        return

    header = [h.strip().lower() for h in raw_header]
    mapped = [_CSV_COLUMN_ALIASES.get(h) for h in header]

    for row in reader:
        if not row:
            continue
        record: dict = {}
        for idx, field in enumerate(mapped):
            if field and idx < len(row):
                record[field] = row[idx].strip()
        if record.get("vendor") and record.get("product") and record.get("id"):
            records.append(record)


_CVE_DB: List[dict] = _load_builtin_cves() + _load_custom_csvs()


def _parse_version(version_str: str) -> Optional[Tuple[int, ...]]:
    """将版本字符串解析为可比较的整数元组

    示例：
      "2.4.49"  → (2, 4, 49)
      "8.5p1"   → (8, 5)
      "7"       → (7,)
      "abc"     → None
    """
    if not version_str:
        return None
    cleaned = re.sub(r"[^0-9.].*", "", version_str.strip())
    if not cleaned:
        return None
    try:
        return tuple(int(seg) for seg in cleaned.split("."))
    except (ValueError, TypeError):
        return None


def _compare_versions(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    """比较两个版本元组，返回 -1（a<b）、0（a==b）、1（a>b）

    长度不一致时，短的用 0 补齐（如 (2, 4) vs (2, 4, 0) 视为相等）
    """
    max_len = max(len(a), len(b))
    a_padded = a + (0,) * (max_len - len(a))
    b_padded = b + (0,) * (max_len - len(b))
    if a_padded < b_padded:
        return -1
    if a_padded > b_padded:
        return 1
    return 0


def _version_in_range(version_str: Optional[str], range_str: str) -> bool:
    """判断检测到的版本是否在 CVE 的 version_range 内

    range_str 支持的格式：
      - "*"                     → 全版本命中
      - ""（空字符串）           → 视为全版本
      - "<=2.4.48"              → version <= 2.4.48
      - "<2.4.48"               → version < 2.4.48
      - ">=8.5p1,<=9.3p2"      → 区间，多个条件 AND 逻辑
    """
    if not range_str or range_str == "*":
        return True

    if not version_str:
        return True

    ver = _parse_version(version_str)
    if ver is None:
        return True

    conditions = [c.strip() for c in range_str.split(",")]
    for cond in conditions:
        if not cond:
            continue
        m = re.match(r"([<>=!]+)\s*(.+)", cond)
        if not m:
            continue
        op = m.group(1)
        target_str = m.group(2).strip()
        target = _parse_version(target_str)
        if target is None:
            continue
        cmp = _compare_versions(ver, target)
        if op == "<=" and cmp > 0:
            return False
        if op == "<" and cmp >= 0:
            return False
        if op == ">=" and cmp < 0:
            return False
        if op == ">" and cmp <= 0:
            return False
        if op == "==" and cmp != 0:
            return False
        if op == "!=" and cmp == 0:
            return False

    return True


def match_service(service: ServiceInfo) -> List[Vulnerability]:
    """对单个 ServiceInfo 匹配 CVE 数据库，返回命中的漏洞列表

    匹配流程：
      1. 遍历 CVE 库，筛选 vendor+product 相同的条目
      2. 对筛选结果检查 version_range
      3. 有精确版本 → confidence 0.9；无版本 → confidence 0.5
    """
    matched: List[Vulnerability] = []

    for cve in _CVE_DB:
        if not _field_match(cve.get("vendor"), service.vendor):
            continue
        if not _field_match(cve.get("product"), service.product):
            continue

        version_match = _version_in_range(
            service.version,
            cve.get("version_range", ""),
        )
        if not version_match:
            continue

        if service.version:
            confidence = 0.9
        else:
            confidence = 0.5

        matched.append(Vulnerability(
            cve_id=cve["id"],
            severity=cve.get("severity", "UNKNOWN"),
            cvss_score=cve.get("cvss_score"),
            description=cve.get("description", ""),
            matched_on={
                "vendor": service.vendor,
                "product": service.product,
                "version": service.version,
            },
            confidence=confidence,
            references=cve.get("references", []),
        ))

    return matched


def _field_match(cve_value: Optional[str], service_value: Optional[str]) -> bool:
    """比较两个字段是否匹配（忽略大小写，任意一方为 None 则不匹配）"""
    if not cve_value or not service_value:
        return False
    return cve_value.lower() == service_value.lower()


def match_host(services: List[ServiceInfo]) -> List[Vulnerability]:
    """对单台主机所有服务进行 CVE 匹配，去重后返回"""
    seen: set = set()
    results: List[Vulnerability] = []
    for svc in services:
        for vuln in match_service(svc):
            if vuln.cve_id not in seen:
                seen.add(vuln.cve_id)
                results.append(vuln)
    return results


def match_all(services_by_host: List[List[ServiceInfo]]) -> List[List[Vulnerability]]:
    """CVE 匹配主入口 — 对多台主机的服务列表批量匹配"""
    return [match_host(host_services) for host_services in services_by_host]
