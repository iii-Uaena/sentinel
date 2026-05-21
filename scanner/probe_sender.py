"""协议探测发送器 — 向 OPEN 端口发送协议特定的探测载荷，收集原始响应数据

流水线位置：port_scanner → HostResult → probe_sender → ProbeResult → fingerprinter → ServiceInfo
"""

import asyncio
import ssl
from typing import Dict, List, Optional

from models import HostResult, PortStatus, ProbeResult


async def _read_some(reader: asyncio.StreamReader, timeout: float) -> Optional[bytes]:
    """从 StreamReader 读取最多 4096 字节，超时返回 None（不抛异常）"""
    try:
        return await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except asyncio.TimeoutError:
        return None


async def grab_banner(host: str, port: int, timeout: float = 2.0) -> ProbeResult:
    """通用 banner 抓取 — 连接后先被动读，无数据则发送 \\r\\n 触发响应

    适用协议：SSH、FTP、SMTP、POP3、IMAP、MySQL、PostgreSQL、Redis 等

    探测逻辑：
      1. 建立 TCP 连接
      2. 被动等待服务器发送 banner（如 SSH-2.0-OpenSSH_8.1）
      3. 如果服务器不主动发送，则写入 \\r\\n 触发响应
      4. 连接失败不抛异常，错误信息记入 ProbeResult.error
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        banner = await _read_some(reader, timeout)
        if not banner:
            writer.write(b"\r\n")
            await writer.drain()
            banner = await _read_some(reader, timeout)

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return ProbeResult(
            host=host,
            port=port,
            probe_type="generic_banner",
            banner=banner.decode("utf-8", errors="replace").strip() if banner else None,
        )

    except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
        return ProbeResult(
            host=host,
            port=port,
            probe_type="generic_banner",
            error=str(e),
        )


def _parse_http_headers(raw_response: str) -> Dict[str, str]:
    """从原始 HTTP 响应文本中提取响应头，key 统一转为小写

    输入示例：
      "HTTP/1.1 200 OK\\r\\nServer: Apache/2.4.49\\r\\nContent-Type: text/html\\r\\n\\r\\n<body>..."

    解析规则：
      - 首行为状态行，跳过
      - 后续行直到遇到空行为止，按 "Key: Value" 格式解析
      - 头名转为小写
    """
    headers: Dict[str, str] = {}
    lines = raw_response.split("\r\n")
    for line in lines[1:]:
        stripped = line.strip()
        if not stripped:
            break
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return headers


async def http_get(host: str, port: int, timeout: float = 2.0) -> ProbeResult:
    """HTTP GET 探测 — 发送 HTTP/1.0 GET 请求，解析响应头

    用 HTTP/1.0 而非 1.1 的原因：
      - 1.0 服务器默认在响应结束后关闭连接，无需处理 chunked 编码
      - 1.1 默认 keep-alive + chunked，需要额外解析逻辑
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        request = (
            f"GET / HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Sentinel/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        response = b""
        while True:
            chunk = await _read_some(reader, timeout)
            if not chunk:
                break
            response += chunk

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        response_text = response.decode("utf-8", errors="replace")
        headers = _parse_http_headers(response_text)

        return ProbeResult(
            host=host,
            port=port,
            probe_type="http_get",
            banner=response_text[:4096],
            headers=headers,
        )

    except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
        return ProbeResult(
            host=host,
            port=port,
            probe_type="http_get",
            error=str(e),
        )


async def tls_https_get(host: str, port: int, timeout: float = 3.0) -> ProbeResult:
    """TLS + HTTPS GET 探测 — TLS 握手（不验证证书 + SNI）后发送 HTTP GET

    与 http_get 的区别：
      1. 通过 ssl 标准库升级为 TLS 通道（不依赖 openssl）
      2. 启用 SNI 让服务器返回正确的证书
      3. 额外提取 TLS 证书 subject / issuer / not_after

    超时默认 3.0s（比纯 TCP 多 1 秒），因为 TLS 握手需要额外一次往返。
    捕获 ssl.SSLError：端口 OPEN 但可能不支持 TLS，probe_port 层会回退到 http_get。
    """
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context, server_hostname=host),
            timeout=timeout,
        )

        tls_info: dict = {}
        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:
                cert = sock.getpeercert()
                if cert:
                    tls_info["subject"] = dict(cert.get("subject", []))
                    tls_info["issuer"] = dict(cert.get("issuer", []))
                    tls_info["not_after"] = cert.get("notAfter", "")
            except Exception:
                pass

        request = (
            f"GET / HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Sentinel/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        response = b""
        while True:
            chunk = await _read_some(reader, timeout)
            if not chunk:
                break
            response += chunk

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        response_text = response.decode("utf-8", errors="replace")
        headers = _parse_http_headers(response_text)

        return ProbeResult(
            host=host,
            port=port,
            probe_type="tls_https_get",
            banner=response_text[:4096],
            headers=headers,
            tls_info=tls_info,
        )

    except (ConnectionRefusedError, asyncio.TimeoutError, OSError, ssl.SSLError) as e:
        return ProbeResult(
            host=host,
            port=port,
            probe_type="tls_https_get",
            error=str(e),
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 调度与聚合
# ═══════════════════════════════════════════════════════════════════════════════

_TLS_PORTS = {443, 8443}
_HTTP_PORTS = {80, 8080, 8000, 8888}


async def probe_port(host: str, port: int, timeout: float = 2.0) -> ProbeResult:
    """根据端口号选择探测策略并执行探测

    策略路由：
      443/8443 → tls_https_get，失败回退 http_get
      80/8080/8000/8888 → http_get
      其他端口 → grab_banner
    """
    if port in _TLS_PORTS:
        tls_timeout = max(timeout, 3.0)
        result = await tls_https_get(host, port, tls_timeout)
        if result.error is not None:
            result = await http_get(host, port, timeout)
        return result

    if port in _HTTP_PORTS:
        return await http_get(host, port, timeout)

    return await grab_banner(host, port, timeout)


async def probe_host(host_result: HostResult, timeout: float = 2.0) -> List[ProbeResult]:
    """对单台主机所有 OPEN 端口并发执行协议探测

    Args:
        host_result: port_scanner 产出的单台主机扫描结果
        timeout: 单个探测的超时秒数

    Returns:
        每个 OPEN 端口的探测结果列表；CLOSED/FILTERED/ERROR 端口不触发探测
    """
    tasks = [
        probe_port(host_result.host, p.port, timeout)
        for p in host_result.ports
        if p.status == PortStatus.OPEN
    ]
    return await asyncio.gather(*tasks)
