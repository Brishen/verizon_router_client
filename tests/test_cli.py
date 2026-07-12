import json

import pytest
from click.testing import CliRunner

from verizon_router_client import cli as cli_module
from verizon_router_client.cli import cli

pytestmark = pytest.mark.usefixtures("isolated_env")


class FakeClient:
    def get_uptime_seconds(self):
        return 1234

    def get_wan_ipv4(self):
        return "203.0.113.1"

    def get_wan_ipv6(self):
        return None

    def get_wan_dns_servers(self):
        return ["198.51.100.1"]

    def fetch_known_devices(self):
        return [
            {"mac": "aa", "name": "up", "hostname": "up", "ip": "1", "activity": 1,
             "time_last_active": "now"},
            {"mac": "bb", "name": "down", "hostname": "down", "ip": "2", "activity": 0,
             "time_last_active": "then"},
        ]

    def get_host_traffic_stats(self):
        return {3600: {"aa": {"bytes_tx": 1}}, 86400: {"aa": {"bytes_tx": 2}}}


@pytest.fixture
def fake_connect(monkeypatch):
    captured = {}

    def _connect(settings):
        captured["settings"] = settings
        return FakeClient()

    monkeypatch.setattr(cli_module, "connect", _connect)
    return captured


@pytest.fixture
def runner():
    return CliRunner()


def test_help_needs_no_credentials(runner):
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "bandwidth" in result.output


def test_missing_password_is_usage_error(runner):
    result = runner.invoke(cli, ["status"])
    assert result.exit_code != 0
    assert "password" in result.output.lower()
    # And no network/login was attempted (would have raised on connect).


def test_status_outputs_json(runner, fake_connect):
    result = runner.invoke(cli, ["--password", "pw", "status"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data == {
        "uptime_seconds": 1234,
        "wan_ipv4": "203.0.113.1",
        "wan_ipv6": None,
        "wan_dns_servers": ["198.51.100.1"],
    }


def test_flags_override_settings(runner, fake_connect):
    result = runner.invoke(
        cli,
        ["--base-url", "https://10.9.9.9", "--password", "pw", "--timeout", "3", "status"],
    )
    assert result.exit_code == 0, result.output
    settings = fake_connect["settings"]
    assert settings.base_url == "https://10.9.9.9"
    assert settings.password.get_secret_value() == "pw"
    assert settings.timeout_s == 3.0


def test_devices_active_filter_and_summary(runner, fake_connect):
    result = runner.invoke(cli, ["--password", "pw", "devices", "--active"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)
    assert rows == [
        {"mac": "aa", "name": "up", "ip": "1", "active": True, "last_active": "now"}
    ]


def test_bandwidth_hosts_period_filter(runner, fake_connect):
    result = runner.invoke(
        cli, ["--password", "pw", "bandwidth", "hosts", "--period", "3600"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"aa": {"bytes_tx": 1}}


def test_bandwidth_hosts_rejects_bad_period(runner, fake_connect):
    result = runner.invoke(
        cli, ["--password", "pw", "bandwidth", "hosts", "--period", "42"]
    )
    assert result.exit_code != 0
