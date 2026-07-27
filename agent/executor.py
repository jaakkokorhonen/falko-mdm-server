"""Command dispatch and subprocess execution for falko-agent.
Toteuttaa sallitut MDM-komennot ja palauttaa tulokset.
Ref: LINUX.md — executor.py command dispatch (MVP)
"""
from __future__ import annotations
import json
import logging
import time
import subprocess
from . import inventory

logger = logging.getLogger(__name__)

LINUX_COMMAND_TYPES = frozenset(
    {
        "ShellCommand",
        "GetInventory",
        "RebootDevice",
        "ShutDownDevice",
        "LockScreen",
    }
)

# Viive (sekuntia) ennen reboot/poweroff-komennon suoritusta.
# Antaa poll_loop()-funktiolle aikaa lähettää acknowledged-vastaus palvelimelle
# ennen kuin prosessi sammutetaan. Ilman viivettä vastaus ei välttämättä ehdi perille.
_POWER_CMD_DELAY_S = 2


def _run(cmd: list[str], *, shell: bool = False, timeout: int = 300) -> dict:
    # pylint: disable=subprocess-run-check
    r = subprocess.run(cmd, shell=shell, capture_output=True, timeout=timeout)  # nosec B602
    stdout = r.stdout.decode("utf-8", errors="replace")
    stderr = r.stderr.decode("utf-8", errors="replace")
    out = f"{stdout}\n{stderr}".strip()
    if len(out) > 4096:
        out = out[:4093] + "..."
    return {"status": "acknowledged" if r.returncode == 0 else "error", "output": out, "exit_code": r.returncode}


def _shell(payload: dict) -> dict:
    cmd = payload.get("command")
    if not cmd:
        return {"status": "error", "output": "Missing 'command' in payload", "exit_code": -1}
    return _run(cmd, shell=True)


def _inventory(_: dict) -> dict:
    inv = inventory.collect()
    return {"status": "acknowledged", "output": json.dumps(inv), "exit_code": 0}


def _power(cmd: str) -> callable:
    def handler(_: dict) -> dict:
        time.sleep(_POWER_CMD_DELAY_S)
        return _run(["systemctl", cmd])
    return handler


def _lock(_: dict) -> dict:
    return _run(["loginctl", "lock-sessions"])


_HANDLERS: dict[str, callable] = {
    "ShellCommand": _shell,
    "GetInventory": _inventory,
    "RebootDevice": _power("reboot"),
    "ShutDownDevice": _power("poweroff"),
    "LockScreen": _lock,
}


def dispatch(command_type: str, payload: dict) -> dict:
    """Suorittaa yhden MDM-komennon ja palauttaa tuloksen vakioformaatissa.

    Args:
        command_type: Komennon tyyppi. Tuntematon tyyppi palauttaa error-vastauksen
                      heittämättä poikkeusta.
        payload: Komennon parametrit.

    Returns:
        dict: {"status": "acknowledged"|"error", "output": str, "exit_code": int}
        Tämä rakenne palautetaan aina, eikä funktio heitä poikkeuksia.
    """
    handler = _HANDLERS.get(command_type)
    if not handler:
        err_msg = f"Unknown command type: {command_type}"
        logger.error(err_msg)
        return {"status": "error", "output": err_msg, "exit_code": -1}

    try:
        return handler(payload)
    except Exception as e:
        logger.exception("Failed to execute %s", command_type)
        return {"status": "error", "output": str(e), "exit_code": -1}

