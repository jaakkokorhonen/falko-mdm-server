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


def dispatch(command_type: str, payload: dict) -> dict:
    """Suorittaa yhden MDM-komennon ja palauttaa tuloksen vakioformaatissa.

    Args:
        command_type: Komennon tyyppi. Tuntematon tyyppi palauttaa error-vastauksen
                      heittämättä poikkeusta.
        payload: Komennon parametrit.

    Returns:
        dict: {"status": "acknowledged"|"error", "output": str, "exit_code": int}
        Tämä rakenne palautetaan aina, eikä funktio heitä poikkeuksia.

    Note — ShellCommand ja shell=True:
        shell=True on tarkoituksellinen: admin-käyttäjä voi syöttää mielivaltaisia
        komentoja. MVP:ssä luotetaan siihen, että vain OIDC-todennetut adminit voivat
        lisätä komentoja jonoon. Tuotannossa komentojen tulee olla KMS-allekirjoitettuja
        ennen shell=True:n pitämistä turvallisena — ks. LINUX.md: Release Binary Signing.
        # nosec B602 on asetettu tietoisen harkinnan jälkeen.
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
            # pylint: disable=subprocess-run-check
            res = subprocess.run(  # nosec B602
                cmd, shell=True, capture_output=True, timeout=300
            )
            stdout = res.stdout.decode("utf-8", errors="replace")
            stderr = res.stderr.decode("utf-8", errors="replace")
            output = f"{stdout}\n{stderr}".strip()
            # Katkaistaan output 4096 merkkiin spesifikaation mukaisesti
            if len(output) > 4096:
                output = output[:4093] + "..."
            status = "acknowledged" if res.returncode == 0 else "error"
            return {"status": status, "output": output, "exit_code": res.returncode}

        elif command_type == "GetInventory":
            inv = inventory.collect()
            return {
                "status": "acknowledged",
                "output": json.dumps(inv),
                "exit_code": 0,
            }

        elif command_type == "RebootDevice":
            # Viive ennen komennon suoritusta: antaa poll_loop():lle aikaa lähettää
            # acknowledged-vastaus palvelimelle ennen prosessin sammumista.
            time.sleep(_POWER_CMD_DELAY_S)
            res = subprocess.run(
                ["systemctl", "reboot"], capture_output=True, check=False
            )
            if res.returncode == 0:
                return {"status": "acknowledged", "output": "Reboot initiated", "exit_code": 0}
            return {
                "status": "error",
                "output": res.stderr.decode("utf-8", errors="replace"),
                "exit_code": res.returncode,
            }

        elif command_type == "ShutDownDevice":
            # Sama viive kuin RebootDevice — ks. kommentti yllä.
            time.sleep(_POWER_CMD_DELAY_S)
            res = subprocess.run(
                ["systemctl", "poweroff"], capture_output=True, check=False
            )
            if res.returncode == 0:
                return {"status": "acknowledged", "output": "Shutdown initiated", "exit_code": 0}
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
            return {
                "status": "error",
                "output": res.stderr.decode("utf-8", errors="replace"),
                "exit_code": res.returncode,
            }

    except Exception as e:
        logger.exception("Failed to execute command: %s", command_type)
        return {"status": "error", "output": str(e), "exit_code": -1}

    # Tähän ei pitäisi koskaan päätyä — kaikki LINUX_COMMAND_TYPES-haarat on käsitelty yllä.
    # Jos tähän päädytään, jokin uusi tyyppi on lisätty frozenset:iin ilman dispatch-haaraa.
    logger.error("BUG: dispatch reached unreachable branch for command_type=%s", command_type)
    return {"status": "error", "output": "Unimplemented command logic branch", "exit_code": -1}
