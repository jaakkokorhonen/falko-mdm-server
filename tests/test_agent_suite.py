"""Unit tests for the Falko MDM Linux Agent (falko-agent)."""
from __future__ import annotations
import configparser
import json
import os
import pytest
from agent import config, executor, inventory


def test_agent_config_defaults(monkeypatch):
    """Verify default configurations when no overrides are present."""
    monkeypatch.delenv("FALKO_SERVER_URL", raising=False)
    monkeypatch.delenv("FALKO_POLL_INTERVAL", raising=False)
    monkeypatch.delenv("FALKO_CONF_PATH", raising=False)

    # Re-initialize configuration instance
    conf = config.AgentConfig()
    assert conf.server_url == "https://mdm-api.falko.fi"
    assert conf.poll_interval == 900
    assert str(conf.token_path) == "/etc/falko/device.token"
    assert conf.log_level == "INFO"


def test_agent_config_env_overrides(monkeypatch):
    """Verify environment variable overrides take precedence."""
    monkeypatch.setenv("FALKO_SERVER_URL", "https://test.falko.fi")
    monkeypatch.setenv("FALKO_POLL_INTERVAL", "30")
    monkeypatch.setenv("FALKO_LOG_LEVEL", "DEBUG")

    conf = config.AgentConfig()
    assert conf.server_url == "https://test.falko.fi"
    assert conf.poll_interval == 30
    assert conf.log_level == "DEBUG"


def test_agent_inventory_collection():
    """Verify collect() runs successfully and returns required keys."""
    data = inventory.collect()
    required_keys = {
        "device_id",
        "hostname",
        "os",
        "kernel",
        "arch",
        "cpu",
        "ram_gb",
        "ip_local",
        "agent_version",
    }
    assert required_keys.issubset(data.keys())
    assert isinstance(data["ram_gb"], int)
    assert isinstance(data["device_id"], str)
    assert len(data["device_id"]) == 64 or data["device_id"] == ""


def test_agent_executor_dispatch_unallowed():
    """Verify unknown command type returns error response."""
    res = executor.dispatch("MaliciousCommand", {"command": "rm -rf /"})
    assert res["status"] == "error"
    assert "Unknown command type" in res["output"]


def test_agent_executor_shell_command():
    """Verify ShellCommand execution output is captured."""
    res = executor.dispatch("ShellCommand", {"command": "echo 'hello world'"})
    assert res["status"] == "acknowledged"
    assert res["exit_code"] == 0
    assert "hello world" in res["output"]


def test_agent_executor_get_inventory():
    """Verify GetInventory returns correct JSON output."""
    res = executor.dispatch("GetInventory", {})
    assert res["status"] == "acknowledged"
    assert res["exit_code"] == 0
    data = json.loads(res["output"])
    assert "device_id" in data
