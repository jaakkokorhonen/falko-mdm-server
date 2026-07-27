"""Falko-agentin konfiguraationlukija.
Lukee /etc/falko/agent.conf (INI-formaatti, configparser).
Kaikki arvot voidaan ylikirjoittaa ympäristömuuttujilla.
Ref: LINUX.md — config.py section
"""
from __future__ import annotations
import configparser
import os
from pathlib import Path

_DEFAULT_CONF_PATH = "/etc/falko/agent.conf"


class AgentConfig:
    conf_path: Path   # aktiivinen konfiguraatiotiedoston polku (testeissä ylikirjoitettavissa)
    server_url: str
    poll_interval: int
    token_path: Path
    log_level: str

    def __init__(self) -> None:
        # conf_path tallennetaan instanssiin, jotta testit ja muut moduulit
        # voivat tarkistaa minkä tiedoston perusteella konfiguraatio on ladattu.
        self.conf_path = Path(
            os.environ.get("FALKO_CONF_PATH", _DEFAULT_CONF_PATH)
        )

        cp = configparser.ConfigParser()
        if self.conf_path.exists():
            cp.read(self.conf_path)
        s = cp["falko"] if "falko" in cp else {}

        self.server_url = os.environ.get(
            "FALKO_SERVER_URL", s.get("server_url", "https://mdm-api.falko.fi")
        )
        self.poll_interval = int(
            os.environ.get(
                "FALKO_POLL_INTERVAL", s.get("poll_interval", "900")
            )
        )
        self.token_path = Path(
            os.environ.get(
                "FALKO_TOKEN_PATH",
                s.get("token_path", "/etc/falko/device.token"),
            )
        )
        self.log_level = os.environ.get(
            "FALKO_LOG_LEVEL", s.get("log_level", "INFO")
        )


# Moduulitason singleton, jota muut moduulit tuovat tyyliin: `from .config import CONFIG`
CONFIG = AgentConfig()
