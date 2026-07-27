"""Command dispatch and subprocess execution for falko-agent.
Toteuttaa sallitut MDM-komennot ja palauttaa tulokset.
Ref: LINUX.md — executor.py command dispatch (MVP)
"""
from __future__ import annotations
import json
import logging
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


def dispatch(command_type: str, payload: dict) -> dict:
    """Suorittaa yhden MDM-komennon ja palauttaa tuloksen vakioformaatissa.

    Args:
        command_type: Komennon tyyppi.
        payload: Komennon parametrit.

    Returns:
        dict: {"status": "acknowledged"|"error", "output": str, "exit_code": int}
        Tämä rakenne palautetaan aina, eikä funktio heitä poikkeuksia.
    """
    if command_type not in LINUX_COMMAND_TYPES:
        err_msg = f"Unknown command type: {command_type}"
        logger.error(err_msg)
        return {"status": "error", "output": err_msg, "exit_code": -1}

    try:
        if command_type == "ShellCommand":
            cmd = payload.get("command")
            if not cmd:
                return {
                    "status": "error",
                    "output": "Missing 'command' in payload",
                    "exit_code": -1,
                }
            # shell=True is intentional: ShellCommand payloads are admin-authored and
            # verified by KMS signature (prod). In MVP, only OIDC-authenticated admins
            # can enqueue commands.
            # pylint: disable=subprocess-run-check
            res = subprocess.run(  # nosec B602
                cmd, shell=True, capture_output=True, timeout=300
            )
            stdout = res.stdout.decode("utf-8", errors="replace")
            stderr = res.stderr.decode("utf-8", errors="replace")
            output = f"{stdout}\n{stderr}".strip()
            # Truncate output to 4096 characters per spec
            if len(output) > 4096:
                output = output[:4093] + "..."

            status = "acknowledged" if res.returncode == 0 else "error"
            return {
                "status": status,
                "output": output,
                "exit_code": res.returncode,
            }

        elif command_type == "GetInventory":
            inv = inventory.collect()
            return {
                "status": "acknowledged",
                "output": json.dumps(inv),
                "exit_code": 0,
            }

        elif command_type == "RebootDevice":
            res = subprocess.run(
                ["systemctl", "reboot"], capture_output=True, check=False
            )
            if res.returncode == 0:
                return {
                    "status": "acknowledged",
                    "output": "Reboot initiated",
                    "exit_code": 0,
                }
            else:
                return {
                    "status": "error",
                    "output": res.stderr.decode("utf-8", errors="replace"),
                    "exit_code": res.returncode,
                }

        elif command_type == "ShutDownDevice":
            res = subprocess.run(
                ["systemctl", "poweroff"], capture_output=True, check=False
            )
            if res.returncode == 0:
                return {
                    "status": "acknowledged",
                    "output": "Shutdown initiated",
                    "exit_code": 0,
                }
            else:
                return {
                    "status": "error",
                    "output": res.stderr.decode("utf-8", errors="replace"),
                    "exit_code": res.returncode,
                }

        elif command_type == "LockScreen":
            res = subprocess.run(
                ["loginctl", "lock-sessions"], capture_output=True, check=False
            )
            if res.returncode == 0:
                return {
                    "status": "acknowledged",
                    "output": "Lock screen session command sent",
                    "exit_code": 0,
                }
            else:
                return {
                    "status": "error",
                    "output": res.stderr.decode("utf-8", errors="replace"),
                    "exit_code": res.returncode,
                }

    except Exception as e:
        logger.exception("Failed to execute command: %s", command_type)
        return {"status": "error", "output": str(e), "exit_code": -1}

    return {
        "status": "error",
        "output": "Unimplemented command logic branch",
        "exit_code": -1,
    }
