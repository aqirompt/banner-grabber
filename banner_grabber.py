#!/usr/bin/env python3
"""
banner_grabber.py — 主动式服务 Banner 探测工具
=================================================
通过与目标端口建立真实 TCP 连接，捕获服务主动返回的
握手信息（Banner），识别服务类型、版本及操作系统特征。

用途: 授权渗透测试、安全审计、网络资产管理
作者: security-toolkit
协议: MIT License
"""

import socket
import time
import json
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict
from datetime import datetime

# ──────────────────────────────────────────────
# 日志配置
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# 服务指纹库（主动探测载荷）
# ──────────────────────────────────────────────
SERVICE_PROBES: Dict[int, bytes] = {
    21:  None,           # FTP  — 服务端主动推送
    22:  None,           # SSH  — 服务端主动推送
    25:  None,           # SMTP — 服务端主动推送
    80:  b"HEAD / HTTP/1.0\r\n\r\n",    # HTTP
    443: b"HEAD / HTTP/1.0\r\n\r\n",    # HTTPS（明文层）
    3306: None,          # MySQL — 服务端主动发送握手包
    5432: None,          # PostgreSQL
    6379: b"PING\r\n",  # Redis
}

# ──────────────────────────────────────────────
# 数据类
# ──────────────────────────────────────────────
@dataclass
class BannerResult:
    host:       str
    port:       int
    success:    bool
    banner_raw: Optional[bytes] = None
    banner_str: Optional[str]  = None
    error:      Optional[str]  = None
    latency_ms: Optional[float]= None
    timestamp:  str = field(
        default_factory=lambda: datetime.now().isoformat()
    )

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("banner_raw", None)  # bytes 不可 JSON 序列化
        return d


# ──────────────────────────────────────────────
# 核心函数：单端口 Banner 抓取
# ──────────────────────────────────────────────
def grab_banner(
    host: str,
    port: int,
    timeout: float = 3.0,
    buf_size: int = 4096,
) -> BannerResult:
    """
    与目标 host:port 建立 TCP 连接并抓取 Banner。

    Args:
        host:     目标 IP 或域名
        port:     目标端口
        timeout:  连接与接收超时（秒）
        buf_size: recv 缓冲区大小（字节）

    Returns:
        BannerResult 数据对象
    """
    start = time.perf_counter()
    probe = SERVICE_PROBES.get(port)       # 按端口选择探测载荷

    try:
        # 创建 IPv4 TCP 套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # TCP 三次握手（connect 内部完成）
        sock.connect((host, port))

        # HTTP 等被动服务：需先发送请求
        if probe is not None:
            sock.sendall(probe)

        # 接收 Banner 数据
        banner_raw = sock.recv(buf_size)
        latency = (time.perf_counter() - start) * 1000

        # 解码：忽略无法解码的字节（二进制协议中常见）
        banner_str = banner_raw.decode("utf-8", errors="replace").strip()

        logger.info(f"[+] {host}:{port}  {banner_str[:80]!r}")

        return BannerResult(
            host=host, port=port,
            success=True,
            banner_raw=banner_raw,
            banner_str=banner_str,
            latency_ms=round(latency, 2),
        )

    except socket.timeout:
        return BannerResult(host=host, port=port, success=False,
                             error="connection timed out")
    except ConnectionRefusedError:
        return BannerResult(host=host, port=port, success=False,
                             error="connection refused")
    except Exception as e:
        return BannerResult(host=host, port=port, success=False,
                             error=str(e))
    finally:
        sock.close()


# ──────────────────────────────────────────────
# 批量并发扫描器
# ──────────────────────────────────────────────
def scan_host(
    host: str,
    ports: List[int],
    timeout: float = 3.0,
    max_workers: int = 20,
) -> List[BannerResult]:
    """多端口并发 Banner 扫描，返回有序结果列表。"""
    results: Dict[int, BannerResult] = {}

    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as ex:
        futures = {
            ex.submit(grab_banner, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            port = futures[future]
            results[port] = future.result()

    return [results[p] for p in ports if p in results]


# ──────────────────────────────────────────────
# CLI 入口

def main():
    parser = argparse.ArgumentParser(
        description="Banner Grabber — 主动式服务指纹识别工具"
    )
    parser.add_argument("--host",    required=True,  help="目标主机 IP 或域名")
    parser.add_argument("--port",    type=int,        help="单端口")
    parser.add_argument("--ports",                    help="多端口，逗号分隔")
    parser.add_argument("--timeout", type=float, default=3.0, help="超时（秒）")
    parser.add_argument("--output",                    help="JSON 输出文件路径")
    args = parser.parse_args()

    # 端口列表构建
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    elif args.port:
        ports = [args.port]
    else:
        ports = [21, 22, 25, 80, 3306, 5432, 6379]  # 默认常见端口

    results = scan_host(args.host, ports, timeout=args.timeout)

    # 打印结果
    print(f"\n{'─'*60}")
    print(f"  扫描目标: {args.host}  |  端口数: {len(ports)}")
    print(f"{'─'*60}")
    for r in results:
        status = "✓" if r.success else "✗"
        if r.success:
            print(f"  [{status}] Port {r.port:5d}  {r.latency_ms:>6.1f}ms  {r.banner_str[:60]!r}")
        else:
            print(f"  [{status}] Port {r.port:5d}  {r.error}")

    # 可选 JSON 输出
    if args.output:
        with open(args.output, "w") as f:
            json.dump([r.to_dict() for r in results], f,
                      ensure_ascii=False, indent=2)
        logger.info(f"结果已写入: {args.output}")


if __name__ == "__main__":
    main()
