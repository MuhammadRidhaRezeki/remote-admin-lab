"""Allowlisted local system information collection."""

from __future__ import annotations

import platform
import time
from pathlib import Path

import psutil

from shared.models import DeviceIdentity

AGENT_VERSION = "1.0.0"


def private_ips() -> list[str]:
    found: list[str] = []
    for _name, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family == psutil.AF_LINK:
                continue
            if getattr(address, "family", None) == 2 and address.address:
                if not address.address.startswith("127.") and address.address not in found:
                    found.append(address.address)
    return found or ["127.0.0.1"]


def device_identity() -> DeviceIdentity:
    return DeviceIdentity(
        device_id="pending",
        hostname=platform.node() or "unknown",
        os_name=platform.system() or "unknown",
        os_version=platform.version() or "unknown",
        python_version=platform.python_version(),
        private_ips=private_ips(),
        agent_version=AGENT_VERSION,
    )


def system_snapshot(agent_status: str) -> dict[str, object]:
    identity = device_identity()
    disk_root = Path.home().anchor or str(Path.cwd())
    disk = psutil.disk_usage(disk_root)
    memory = psutil.virtual_memory()
    return {
        "hostname": identity.hostname,
        "os_name": identity.os_name,
        "os_version": identity.os_version,
        "python_version": identity.python_version,
        "private_ips": identity.private_ips,
        "cpu_percent": round(psutil.cpu_percent(interval=0.1), 2),
        "cpu_cores_logical": psutil.cpu_count(logical=True) or 0,
        "memory_total_gb": round(memory.total / 1024**3, 2),
        "memory_used_gb": round(memory.used / 1024**3, 2),
        "disk_total_gb": round(disk.total / 1024**3, 2),
        "disk_free_gb": round(disk.free / 1024**3, 2),
        "network_interfaces": [
            {"name": name, "addresses": [a.address for a in addresses]}
            for name, addresses in psutil.net_if_addrs().items()
        ],
        "agent_status": agent_status,
        "uptime_seconds": int(time.time() - psutil.boot_time()),
    }
