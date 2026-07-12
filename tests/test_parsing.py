import pytest

from verizon_router_client.cr1000a import VerizonRouterClient, _parse_js_literal

BANDWIDTH_JS = """\
addROD("get_history_rates", [['11466','56717'],['12661','9102'],['45582415','2510582701021']]);
addROD("known_device_list", { "known_devices": [ { "mac": "00:00:5e:00:53:01", "hostname": "host1", "ip": "192.0.2.100", "mac_vendor": "Acme, Inc.", "device_os": "(null)", "activity": 1, "vendor": "n\\/a" } ] });
addROD("hosts_trafstat", {
    "3600": {
        "00:00:5e:00:53:01": {
            "mac": "00:00:5e:00:53:01",
            "packets_tx": 126,
            "bytes_tx": 20486,
            "packets_rx": 35,
            "bytes_rx": 4561
        }
    }
}
);

//fsam ui update
addROD("fsam_update", { "fsam_ui": [ ] });
"""

CFG_JS = """\
addCfg("dns_name0", "x7f3a", "nas");
addCfg("dns_ip0", "y2b91", "192.168.1.10");
addCfg("dns_name1", "z0c4d", "");
addCfg("dns_ip1", "w9e12", "");
"""


class TestParseAddROD:
    def test_parses_all_entries(self):
        rod = VerizonRouterClient._parse_addrod(BANDWIDTH_JS)
        assert set(rod) == {
            "get_history_rates",
            "known_device_list",
            "hosts_trafstat",
            "fsam_update",
        }

    def test_nested_lists(self):
        rod = VerizonRouterClient._parse_addrod(BANDWIDTH_JS)
        rates = rod["get_history_rates"]
        assert rates[0] == ["11466", "56717"]
        assert rates[2][1] == "2510582701021"

    def test_multiline_object_with_trailing_paren_on_own_line(self):
        rod = VerizonRouterClient._parse_addrod(BANDWIDTH_JS)
        stats = rod["hosts_trafstat"]
        assert stats["3600"]["00:00:5e:00:53:01"]["bytes_tx"] == 20486

    def test_escaped_slashes_unescaped(self):
        rod = VerizonRouterClient._parse_addrod(BANDWIDTH_JS)
        device = rod["known_device_list"]["known_devices"][0]
        assert device["vendor"] == "n/a"


class TestParseAddCfg:
    def test_parses_entries_with_enc_names(self):
        cfg = VerizonRouterClient._parse_addcfg(CFG_JS)
        assert cfg["dns_name0"].enc_name == "x7f3a"
        assert cfg["dns_name0"].val == "nas"
        assert cfg["dns_ip0"].val == "192.168.1.10"
        assert cfg["dns_name1"].val == ""


class TestParseJsLiteral:
    @pytest.mark.parametrize(
        ("src", "expected"),
        [
            ("null", None),
            ("true", True),
            ("false", False),
            ("'12345'", "12345"),
            ('"quoted"', "quoted"),
            ("[1, null, true]", [1, None, True]),
            ('{"a": false}', {"a": False}),
        ],
    )
    def test_literals(self, src, expected):
        assert _parse_js_literal(src) == expected


class TestExtractJsObjectArgument:
    def test_nested_braces(self):
        src = 'addROD("x", {"a": {"b": [1, {"c": 2}]}});'
        out = VerizonRouterClient._extract_js_object_argument(src, 'addROD("x",')
        assert out == '{"a": {"b": [1, {"c": 2}]}}'

    def test_braces_inside_strings_ignored(self):
        src = 'addROD("x", {"a": "}{"});'
        out = VerizonRouterClient._extract_js_object_argument(src, 'addROD("x",')
        assert out == '{"a": "}{"}'

    def test_missing_prefix_raises(self):
        with pytest.raises(ValueError):
            VerizonRouterClient._extract_js_object_argument("nothing", 'addROD("x",')


class TestParseKnownDevices:
    def test_parses_device_list(self):
        devices = VerizonRouterClient.parse_known_devices(BANDWIDTH_JS)
        assert len(devices) == 1
        assert devices[0]["mac"] == "00:00:5e:00:53:01"
