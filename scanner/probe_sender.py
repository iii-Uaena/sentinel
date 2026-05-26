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

# 构造 SMB1 Negotiate Protocol Request（端口 445）
_smb_header = bytes([
    0xFF, 0x53, 0x4D, 0x42,  # Protocol: \xffSMB
    0x72,                      # Command: Negotiate (0x72)
    0x00, 0x00, 0x00, 0x00,   # NT Status
    0x18,                      # Flags: canonicalized + case-insensitive
    0x01, 0xC8,                # Flags2: NT status + long names + unicode
    0x00, 0x00,                # PID High
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Security Features
    0x00, 0x00,                # Reserved
    0x00, 0x00,                # TID
    0xFE, 0xFF,                # PID Low
    0x00, 0x00,                # UID
    0x00, 0x00,                # MID
])
_smb_dialects = b""
for _d in [b"PC NETWORK PROGRAM 1.0", b"LANMAN1.0", b"LM1.2X002",
           b"LANMAN2.1", b"NT LM 0.12", b"SMB 2.002"]:
    _smb_dialects += b"\x02" + _d + b"\x00"
_smb_msg = _smb_header + b"\x00" + len(_smb_dialects).to_bytes(2, "little") + _smb_dialects
# NetBIOS Session 头: type=0x00 (会话消息), length=24-bit 大端
_SMB_NEGOTIATE = bytes([
    0x00,
    (len(_smb_msg) >> 16) & 0xFF,
    (len(_smb_msg) >> 8) & 0xFF,
    len(_smb_msg) & 0xFF,
]) + _smb_msg

# TPKT + COTP 连接请求 + RDP 协商请求（端口 3389）
_RDP_NEGOTIATION = bytes([
    0x03, 0x00, 0x00, 0x13,  # TPKT: version=3, reserved=0, length=19
    0x0E,                      # COTP length (14 bytes including this)
    0xE0,                      # PDU type: CR (Connection Request)
    0x00, 0x00,                # DST-REF
    0x00, 0x00,                # SRC-REF
    0x00,                      # Options: class 0, no extended formats
    0x01,                      # RDP Negotiation Request type
    0x00,                      # Flags
    0x00, 0x00,                # Length (bytes following)
    0x00, 0x00, 0x00, 0x00,   # Requested Protocols (0 = negotiate)
])

# 协议专用端口集合
_SMB_PORTS = {445}
_RDP_PORTS = {3389}


async def _smb_probe(host: str, port: int, timeout: float = 2.0) -> ProbeResult:
    """Send SMB Negotiate Protocol Request (port 445), detect SMB/Samba by response"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.write(_SMB_NEGOTIATE)
        await writer.drain()
        raw = await _read_some(reader, timeout)

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if raw and raw[:4] == b"\xffSMB":
            # SMB 响应确认 — 注入可读标签供 fingerprinter 匹配
            banner = "SMB Negotiate Response"
        else:
            banner = raw.decode("utf-8", errors="replace").strip() if raw else None

        return ProbeResult(
            host=host,
            port=port,
            probe_type="generic_banner",
            banner=banner,
        )
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
        return ProbeResult(host=host, port=port, probe_type="generic_banner", error=str(e))


async def _rdp_probe(host: str, port: int, timeout: float = 2.0) -> ProbeResult:
    """发送 TPKT 连接请求（端口 3389），通过响应 magic bytes 检测 RDP"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.write(_RDP_NEGOTIATION)
        await writer.drain()
        raw = await _read_some(reader, timeout)

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if raw and len(raw) >= 4 and raw[:1] == b"\x03" and raw[1:2] == b"\x00":
            # TPKT 头检测到（版本 3，保留字段 0）
            banner = "TPKT RDP Negotiation Response"
        else:
            banner = raw.decode("utf-8", errors="replace").strip() if raw else None

        return ProbeResult(
            host=host,
            port=port,
            probe_type="generic_banner",
            banner=banner,
        )
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
        return ProbeResult(host=host, port=port, probe_type="generic_banner", error=str(e))


async def probe_port(host: str, port: int, timeout: float = 2.0) -> ProbeResult:
    """根据端口号选择探测策略并执行探测

    策略路由：
      443/8443 → tls_https_get，失败回退 http_get
      80/8080/8000/8888 → http_get
      其他端口 → grab_banner
    """
    if port in _TLS_PORTS:
        # TLS 端口：超时比纯 TCP 长（TLS 多一次往返）
        tls_timeout = max(timeout, 3.0)
        result = await tls_https_get(host, port, tls_timeout)
        if result.error is not None:
            # TLS 可能因证书/协议不匹配失败，回退到纯 HTTP GET
            result = await http_get(host, port, timeout)
        return result

    if port in _HTTP_PORTS:
        return await http_get(host, port, timeout)

    if port in _SMB_PORTS:
        return await _smb_probe(host, port, timeout)

    if port in _RDP_PORTS:
        return await _rdp_probe(host, port, timeout)

    # 非特定协议端口：使用通用 banner 抓取
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
