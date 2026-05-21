"""TCP 端口扫描器 — asyncio 并发 TCP Connect 扫描，四状态分类（open/closed/filtered/error）"""

import asyncio
import time
from typing import List, Optional

from models import HostResult, PortInfo, PortStatus


async def scan_single_port(host: str, port: int, timeout: float = 2.0) -> PortInfo:
    """对单个 IP:Port 执行一次 TCP Connect，返回 PortInfo

    状态判定路径：
    - 连接成功 → OPEN，记录 rtt_ms
    - ConnectionRefusedError → CLOSED（对方 RST，端口明确关闭）
    - TimeoutError → FILTERED（超时无响应，被防火墙丢弃）
    - OSError → ERROR（网络不可达等）
    """
    reason = ""
    rtt_ms: Optional[float] = None
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        rtt_ms = round((time.perf_counter() - t0) * 1000, 2)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return PortInfo(port=port, status=PortStatus.OPEN, rtt_ms=rtt_ms)

    except ConnectionRefusedError:
        reason = "connection refused"
        return PortInfo(port=port, status=PortStatus.CLOSED, reason=reason)

    except asyncio.TimeoutError:
        reason = f"timeout {int(timeout * 1000)}ms"
        return PortInfo(port=port, status=PortStatus.FILTERED, reason=reason)

    except OSError as e:
        reason = str(e)
        return PortInfo(port=port, status=PortStatus.ERROR, reason=reason)


async def scan_single_port_with_retry(
    host: str,
    port: int,
    timeout: float = 2.0,
    retries: int = 1,
    semaphore: Optional[asyncio.Semaphore] = None,
) -> PortInfo:
    """在 scan_single_port 之上叠加重试 + 并发控制

    重试规则：
    - OPEN / CLOSED 是确定性结果，不重试
    - FILTERED / ERROR 是瞬时状态，重试 retries 次（总计最多 1+retries 次尝试）

    并发控制：
    - Semaphore 包裹整个扫描（含重试），被调用方传入而非自行创建
    - 理由：Semaphore 应由顶层 scan() 创建并传递，保证所有主机共享同一个并发上限
    """
    async def _do_scan():
        result = await scan_single_port(host, port, timeout)
        for _ in range(retries):
            if result.status in (PortStatus.OPEN, PortStatus.CLOSED):
                break
            result = await scan_single_port(host, port, timeout)
        return result

    if semaphore:
        async with semaphore:
            return await _do_scan()
    return await _do_scan()


async def scan_host(
    host: str,
    ports: List[int],
    semaphore: asyncio.Semaphore,
    timeout: float = 2.0,
    retries: int = 1,
) -> HostResult:
    """扫描一台主机的所有端口，返回 HostResult

    并发发起所有端口的扫描任务，共享全局 Semaphore 控制并发度。
    主机状态判定：至少一个端口 OPEN → "up"，否则 → "down"。
    保留全部端口的扫描结果（含 closed/filtered/error），不丢弃。
    """
    tasks = [
        scan_single_port_with_retry(host, port, timeout, retries, semaphore)
        for port in ports
    ]
    port_results: List[PortInfo] = await asyncio.gather(*tasks)

    host_status = "up" if any(
        p.status == PortStatus.OPEN for p in port_results
    ) else "down"

    return HostResult(host=host, status=host_status, ports=port_results)


async def scan(
    targets: List[str],
    ports: List[int],
    concurrency: int = 100,
    timeout: float = 2.0,
    retries: int = 1,
) -> List[HostResult]:
    """端口扫描主入口 — 并发扫描多台主机的指定端口

    在此创建全局 Semaphore，所有主机的所有端口共享同一个并发上限。

    Args:
        targets: 目标 IP 地址列表
        ports: 待扫描端口号列表
        concurrency: 最大并发 TCP 连接数（Semaphore 上限）
        timeout: 单个连接超时秒数
        retries: FILTERED/ERROR 状态的重试次数

    Returns:
        每台主机的扫描结果列表，顺序与 targets 一致
    """
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [scan_host(target, ports, semaphore, timeout, retries)
             for target in targets]
    results = await asyncio.gather(*tasks)
    return list(results)
