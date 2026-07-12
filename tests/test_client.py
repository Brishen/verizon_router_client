import json

import pytest

from verizon_router_client.cr1000a import (
    VerizonRouterClient,
    arc_md5,
    luci_password,
)
from tests.conftest import FakeResponse

STATUS_JS = """\
addROD("uptime", '123456');
addROD("get_wan4_ip", '203.0.113.10');
addROD("cgi_wan_ip6_addr", '2001:db8::1');
addCfg("wan_ip4_dns", "e1", "198.51.100.1 198.51.100.2");
"""

DNS_JS = """\
addCfg("dns_name0", "e0", "nas");
addCfg("dns_ip0", "e1", "192.168.1.10");
addCfg("dns_name1", "e2", "");
addCfg("dns_ip1", "e3", "");
addCfg("dns_name2", "e4", "printer");
addCfg("dns_ip2", "e5", "192.168.1.20");
addCfg("dns_ipv6_name0", "e6", "nas6");
addCfg("dns_ipv6_ip0", "e7", "fd00::10");
"""

BANDWIDTH_JS = """\
addROD("get_history_rates", [['11466','56717'],['12661','9102'],['45582415','2510582701021']]);
addROD("hosts_trafstat", {
    "3600": {
        "00:00:5e:00:53:01": {
            "mac": "00:00:5e:00:53:01",
            "packets_tx": 126,
            "bytes_tx": 20486,
            "packets_rx": 35,
            "bytes_rx": 4561
        },
        "00:00:5e:00:53:02": {
            "mac": "00:00:5e:00:53:02",
            "packets_tx": 605,
            "bytes_tx": 304827,
            "packets_rx": 595,
            "bytes_rx": 286236
        }
    },
    "86400": {
        "00:00:5e:00:53:01": {
            "mac": "00:00:5e:00:53:01",
            "packets_tx": 12784,
            "bytes_tx": 2232895,
            "packets_rx": 2956,
            "bytes_rx": 429298
        }
    }
}
);
"""

FORWARD_JS = """\
addROD("portforwardings", {"portforwardings": [{"id": 7, "name": "ssh", "privateIP": "192.168.1.20", "forward_port": "22", "port_rule_id": 3}]});
addROD("upnpportforwardings", [null, {"id": 1}, null]);
addROD("readonly_portforwardings", [null]);
addROD("portrules", {"portrules": [{"id": 3, "ports": [{"dest_port": 22}]}]});
addROD("schedulerules", null);
addROD("reservePort", null);
"""


class TestStatus:
    def test_status_getters(self, make_client):
        client, _ = make_client({"/cgi/cgi_status.js": FakeResponse(text=STATUS_JS)})
        assert client.get_uptime_seconds() == 123456
        assert client.get_wan_ipv4() == "203.0.113.10"
        assert client.get_wan_ipv6() == "2001:db8::1"
        assert client.get_wan_dns_servers() == ["198.51.100.1", "198.51.100.2"]

    def test_empty_status_raises(self, make_client):
        client, _ = make_client({"/cgi/cgi_status.js": FakeResponse(text="<html>login</html>")})
        with pytest.raises(RuntimeError):
            client.fetch_status()

    def test_http_error_propagates(self, make_client):
        client, _ = make_client({"/cgi/cgi_status.js": FakeResponse(status_code=403)})
        with pytest.raises(Exception, match="403"):
            client.fetch_status()


class TestDns:
    def test_v4_entries_skip_empty_slots(self, make_client):
        client, _ = make_client({"/cgi/cgi_dns_server.js": FakeResponse(text=DNS_JS)})
        assert client.get_dns_entries_v4() == [
            {"idx": 0, "name": "nas", "ip": "192.168.1.10"},
            {"idx": 2, "name": "printer", "ip": "192.168.1.20"},
        ]

    def test_v6_entries(self, make_client):
        client, _ = make_client({"/cgi/cgi_dns_server.js": FakeResponse(text=DNS_JS)})
        assert client.get_dns_entries_v6() == [
            {"idx": 0, "name": "nas6", "ip": "fd00::10"},
        ]


class TestBandwidth:
    def test_history_rates_are_ints(self, make_client):
        client, _ = make_client({"/cgi/cgi_bandwith.js": FakeResponse(text=BANDWIDTH_JS)})
        rates = client.get_bandwidth_history_rates()
        assert rates == [
            [11466, 56717],
            [12661, 9102],
            [45582415, 2510582701021],
        ]

    def test_host_traffic_stats_normalized(self, make_client):
        client, _ = make_client({"/cgi/cgi_bandwith.js": FakeResponse(text=BANDWIDTH_JS)})
        stats = client.get_host_traffic_stats()
        assert set(stats) == {3600, 86400}
        assert stats[3600]["00:00:5e:00:53:01"] == {
            "packets_tx": 126,
            "bytes_tx": 20486,
            "packets_rx": 35,
            "bytes_rx": 4561,
        }
        assert len(stats[3600]) == 2

    def test_empty_payload_raises(self, make_client):
        client, _ = make_client({"/cgi/cgi_bandwith.js": FakeResponse(text="")})
        with pytest.raises(RuntimeError):
            client.fetch_bandwidth()


class TestPortForwarding:
    def test_settings_filter_null_entries(self, make_client):
        client, _ = make_client(
            {"/cgi/cgi_firewall_port_forward.js": FakeResponse(text=FORWARD_JS)}
        )
        settings = client.get_port_forwarding_settings()
        assert settings["portforwardings"][0]["id"] == 7
        assert settings["upnpportforwardings"] == [{"id": 1}]
        assert settings["readonly_portforwardings"] == []

    def test_lookup_rule_id_matches_dest_port(self, make_client):
        client, _ = make_client(
            {"/cgi/cgi_firewall_port_forward.js": FakeResponse(text=FORWARD_JS)}
        )
        rule_id = client._lookup_port_forward_id(
            name="ssh", private_ip="192.168.1.20", forward_port=22, dest_port=22
        )
        assert rule_id == 7

    def test_lookup_rule_id_rejects_wrong_dest_port(self, make_client):
        client, _ = make_client(
            {"/cgi/cgi_firewall_port_forward.js": FakeResponse(text=FORWARD_JS)}
        )
        rule_id = client._lookup_port_forward_id(
            name="ssh", private_ip="192.168.1.20", forward_port=22, dest_port=2222
        )
        assert rule_id is None


class TestLogin:
    def test_login_posts_hashed_credentials(self, make_client):
        token = "c" * 32
        client, session = make_client(
            {
                "/loginStatus.cgi": FakeResponse(json_data={"loginToken": token}),
                "/login.cgi": FakeResponse(json_data={}),
            }
        )
        client.login("admin", "hunter2")

        post = next(c for c in session.calls if c["method"] == "POST")
        assert post["path"] == "/login.cgi"
        payload = post["data"]
        assert payload["luci_username"] == arc_md5("admin")
        assert payload["luci_password"] == luci_password("hunter2", token)
        assert payload["luci_token"] == token
        assert "hunter2" not in json.dumps(payload)

    def test_missing_login_token_raises(self, make_client):
        client, _ = make_client(
            {"/loginStatus.cgi": FakeResponse(json_data={"loginToken": "short"})}
        )
        with pytest.raises(RuntimeError, match="loginToken"):
            client.get_login_token()


@pytest.mark.usefixtures("isolated_env")
class TestFromSettings:
    def test_maps_settings_fields(self):
        from verizon_router_client.config import RouterSettings

        settings = RouterSettings(
            base_url="https://10.0.0.1",
            verify_tls=False,
            timeout_s=5.0,
        )
        client = VerizonRouterClient.from_settings(settings)
        assert client.base_url == "https://10.0.0.1"
        assert client.verify_tls is False
        assert client.timeout_s == 5.0
        # IP base URL gets the default SNI hostname.
        assert client.tls_hostname == "mynetworksettings.com"

    def test_unset_verify_tls_keeps_bundled_ca(self):
        from verizon_router_client.config import RouterSettings

        settings = RouterSettings()
        client = VerizonRouterClient.from_settings(settings)
        assert "Verizon Fios Root CA.pem" in str(client.verify_tls)
