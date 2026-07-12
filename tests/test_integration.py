"""Integration tests against a selectable backend.

By default (``--router=auto``) these run against the real router when the
project ``.env`` has credentials, falling back to the in-process mock
service otherwise. Force a backend with ``--router=mock`` or
``--router=real``.

Backend-flexible tests make shape assertions that hold on real hardware and
tighten to exact values on the mock. Tests that need deterministic state
(slot allocation, exact fixture values) or that are unsafe against real
hardware (repeated failed logins) always use the mock, regardless of the
selected backend. Mutating tests create uniquely named entries and clean up
after themselves.
"""

import ipaddress
import uuid
from urllib.parse import urlparse

import pytest
import requests

from verizon_router_client.cr1000a import VerizonRouterClient


def _unique_name(prefix: str = "pytest-vzr") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _lan_test_ip(base_url: str) -> str:
    """An unlikely-to-exist host address in the router's own subnet."""
    host = urlparse(base_url).hostname or ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "192.168.1.250"
    if isinstance(ip, ipaddress.IPv4Address):
        octets = str(ip).split(".")
        octets[3] = "250"
        return ".".join(octets)
    return "192.168.1.250"


# ---- selected backend (mock or real router) ----


@pytest.fixture
def logged_in_client(router_target):
    if router_target.is_mock:
        client = router_target.make_client()
        r = client.login(router_target.username, router_target.password)
        assert r.status_code == 200
        return client
    # Real routers throttle rapid logins; reuse the session-wide login.
    return router_target.logged_in_client


# ---- always-mock fixtures for state-exact / unsafe tests ----


@pytest.fixture
def mock_client(mock_router):
    return VerizonRouterClient(base_url=mock_router.base_url, verify_tls=False)


@pytest.fixture
def mock_logged_in_client(mock_client, mock_router):
    r = mock_client.login(mock_router.state.username, mock_router.state.password)
    assert r.status_code == 200
    return mock_client


class TestLogin:
    def test_login_sets_session_cookie(self, logged_in_client):
        # A subsequent authed endpoint works without re-authenticating.
        assert logged_in_client.get_uptime_seconds() > 0

    # Repeated failed logins could throttle/lock out real hardware: mock only.
    def test_wrong_password_rejected(self, mock_client, mock_router):
        r = mock_client.login(mock_router.state.username, "wrong-password")
        assert r.status_code == 403

    def test_unauthenticated_fetch_gets_login_page(self, mock_client):
        with pytest.raises(RuntimeError):
            mock_client.fetch_status()

    def test_apply_token_requires_login(self, mock_client):
        with pytest.raises(RuntimeError, match="token"):
            mock_client.get_apply_token()


class TestStatus:
    def test_status_getters(self, logged_in_client, router_target):
        uptime = logged_in_client.get_uptime_seconds()
        assert isinstance(uptime, int) and uptime > 0

        wan4 = logged_in_client.get_wan_ipv4()
        if wan4 is not None:
            ipaddress.ip_address(wan4)

        servers = logged_in_client.get_wan_dns_servers()
        assert isinstance(servers, list)
        for server in servers:
            ipaddress.ip_address(server)

        if router_target.is_mock:
            assert uptime == 123456
            assert wan4 == "203.0.113.10"
            assert logged_in_client.get_wan_ipv6() == "2001:db8::1"
            assert servers == ["198.51.100.1", "198.51.100.2"]


class TestDnsRoundTrip:
    def test_add_list_remove(self, logged_in_client):
        name = _unique_name()
        ip = "192.0.2.10"

        try:
            slot = logged_in_client.add_dns_ipv4(name, ip)
            assert {"idx": slot, "name": name, "ip": ip} in (
                logged_in_client.get_dns_entries_v4()
            )
        finally:
            removed = logged_in_client.remove_dns_ipv4_by_hostname(
                name, remove_all=True
            )
        assert removed == [slot]
        assert all(
            e["name"] != name for e in logged_in_client.get_dns_entries_v4()
        )

    # Slot-allocation semantics assume a known-empty table: mock only.
    def test_add_fills_first_empty_slot(self, mock_logged_in_client):
        first = mock_logged_in_client.add_dns_ipv4("a", "192.0.2.1")
        second = mock_logged_in_client.add_dns_ipv4("b", "192.0.2.2")
        assert (first, second) == (0, 1)

        mock_logged_in_client.clear_dns_ipv4_slot(0)
        assert mock_logged_in_client.add_dns_ipv4("c", "192.0.2.3") == 0

    def test_remove_by_ip(self, mock_logged_in_client):
        mock_logged_in_client.add_dns_ipv4("a", "192.0.2.1")
        mock_logged_in_client.add_dns_ipv4("b", "192.0.2.1")

        assert mock_logged_in_client.remove_dns_ipv4_by_ip("192.0.2.1") == [0]
        assert mock_logged_in_client.remove_dns_ipv4_by_ip(
            "192.0.2.1", remove_all=True
        ) == [1]

    def test_mutation_without_login_fails(self, mock_client):
        with pytest.raises((RuntimeError, requests.HTTPError)):
            mock_client.add_dns_ipv4("nas", "192.0.2.10")


class TestPortForwardRoundTrip:
    def test_add_and_remove(self, logged_in_client):
        name = _unique_name()
        rule_id = logged_in_client.add_port_forward(
            name=name,
            private_ip=_lan_test_ip(logged_in_client.base_url),
            forward_port=62222,
            dest_port=62222,
        )
        try:
            settings = logged_in_client.get_port_forwarding_settings()
            assert rule_id in [r["id"] for r in settings["portforwardings"]]
        finally:
            logged_in_client.remove_port_forward(rule_id=rule_id)

        settings = logged_in_client.get_port_forwarding_settings()
        assert rule_id not in [r["id"] for r in settings["portforwardings"]]

    def test_lookup_fallback_finds_created_rule(
        self, mock_logged_in_client, mock_router
    ):
        mock_logged_in_client.add_port_forward(
            name="web", private_ip="192.0.2.30", forward_port=80, dest_port=8080
        )
        rule_id = mock_logged_in_client._lookup_port_forward_id(
            name="web", private_ip="192.0.2.30", forward_port=80, dest_port=8080
        )
        assert rule_id == mock_router.state.forward_rules[0]["id"]


class TestBandwidthAndDevices:
    def test_bandwidth(self, logged_in_client, router_target):
        rates = logged_in_client.get_bandwidth_history_rates()
        assert rates
        assert all(isinstance(v, int) for series in rates for v in series)

        stats = logged_in_client.get_host_traffic_stats()
        for period, hosts in stats.items():
            assert isinstance(period, int)
            for counters in hosts.values():
                assert set(counters) == {
                    "packets_tx",
                    "bytes_tx",
                    "packets_rx",
                    "bytes_rx",
                }

        if router_target.is_mock:
            assert rates[0] == [11466, 56717]
            assert stats[3600]["00:00:5e:00:53:01"]["bytes_tx"] == 20486

    def test_known_devices(self, logged_in_client, router_target):
        devices = logged_in_client.fetch_known_devices()
        assert isinstance(devices, list) and devices
        assert all("mac" in d for d in devices)

        if router_target.is_mock:
            assert devices[0]["mac"] == "00:00:5e:00:53:01"


class TestConnectHelper:
    def test_connect_logs_in_from_settings(self, router_target):
        from verizon_router_client import connect
        from verizon_router_client.config import RouterSettings

        if router_target.is_mock:
            settings = RouterSettings(
                base_url=router_target.mock.base_url,
                username=router_target.username,
                password=router_target.password,
                verify_tls=False,
                _env_file=None,
            )
        else:
            settings = router_target.settings
        client = connect(settings)
        assert client.get_uptime_seconds() > 0

    def test_connect_raises_on_bad_credentials(self, mock_router):
        from verizon_router_client import connect
        from verizon_router_client.config import RouterSettings

        settings = RouterSettings(
            base_url=mock_router.base_url,
            username=mock_router.state.username,
            password="wrong",
            verify_tls=False,
            _env_file=None,
        )
        with pytest.raises(requests.HTTPError):
            connect(settings)
