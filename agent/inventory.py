"""Hardware and OS inventory collection for falko-agent.
Käytetään kahdessa kontekstissa:
1. Agentin käynnistyksessä — lähetetään POST /linux/checkin -pyyntöön
2. GetInventory-komennon vastauksena — palauttaa saman rakenteen
Käyttää ainoastaan standardikirjastoa (ei kolmannen osapuolen riippuvuuksia).
Ref: LINUX.md — inventory.py fields section
"""
from __future__ import annotations
import hashlib
import logging
import os
import platform
import socket
from .__version__ import __version__ as AGENT_VERSION

logger = logging.getLogger(__name__)


def collect() -> dict:
    """Kerää laitteen laitteisto- ja käyttöjärjestelmätiedot.

    Returns:
        dict with keys: device_id, hostname, os, kernel, arch, cpu, ram_gb, ip_local, agent_version

    Raises:
        never — all fields fall back to empty string or default on error.
    """
    res = {
        "device_id": "",
        "hostname": "",
        "os": "",
        "kernel": "",
        "arch": "",
        "cpu": "",
        "ram_gb": 0,
        "ip_local": "",
        "agent_version": AGENT_VERSION,
    }

    # Hostname
    try:
        res["hostname"] = socket.gethostname()
    except Exception as e:
        logger.debug("Failed to get hostname: %s", e)

    # Device ID: SHA-256 of hostname + /etc/machine-id
    try:
        machine_id = ""
        # Look for systemd machine-id or dbus machine-id
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    machine_id = f.read().strip()
                break
        input_str = (res["hostname"] + machine_id).encode("utf-8")
        res["device_id"] = hashlib.sha256(input_str).hexdigest()
    except Exception as e:
        logger.debug("Failed to calculate device_id: %s", e)

    # OS name from /etc/os-release
    try:
        os_name = ""
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=", 1)[1].strip().strip('"')
                        break
        res["os"] = os_name or platform.system()
    except Exception as e:
        logger.debug("Failed to read OS name: %s", e)
        res["os"] = platform.system()

    # Kernel
    try:
        res["kernel"] = platform.release()
    except Exception as e:
        logger.debug("Failed to get kernel release: %s", e)

    # Arch
    try:
        res["arch"] = platform.machine()
    except Exception as e:
        logger.debug("Failed to get architecture: %s", e)

    # CPU model
    try:
        cpu_model = ""
        if os.path.exists("/proc/cpuinfo"):
            with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("model name") or line.startswith("Processor"):
                        cpu_model = line.split(":", 1)[1].strip()
                        break
        res["cpu"] = cpu_model or platform.processor()
    except Exception as e:
        logger.debug("Failed to get CPU model: %s", e)
        res["cpu"] = platform.processor()

    # RAM GB
    try:
        ram_gb = 0
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        mem_kb = int(line.split()[1])
                        ram_gb = int(round(mem_kb / (1024 * 1024)))
                        break
        res["ram_gb"] = ram_gb
    except Exception as e:
        logger.debug("Failed to get RAM: %s", e)

    # Local IP
    try:
        # Standard UDP trick to discover outbound local IP without sending data
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        res["ip_local"] = s.getsockname()[0]
        s.close()
    except Exception as e:
        logger.debug("Failed to get local IP: %s", e)
        # Fallback to resolving hostname
        try:
            res["ip_local"] = socket.gethostbyname(socket.gethostname())
        except Exception:
            pass

    return res
