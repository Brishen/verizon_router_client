"""A minimal in-process mock of the CR1000A web service for integration tests.

Serves the endpoints the client talks to over real HTTP, with the same
auth model: login.cgi verifies the ArcMD5-hashed credentials and issues a
sysauth cookie; the cgi/*.js endpoints return a login page unless that
cookie is presented; mutations require the apply token.

All fixture data uses RFC documentation values (192.0.2.x, 198.51.100.x,
203.0.113.x, 2001:db8::, 00:00:5e:00:53:xx).
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from verizon_router_client.cr1000a import arc_md5, luci_password

LOGIN_TOKEN = "d" * 32
APPLY_TOKEN = "e" * 32
SYSAUTH = "mock-sysauth-value"

LOGIN_PAGE = "<html>please log in</html>"

DNS_SLOTS = 8

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
        }
    }
}
);
"""

OWL_JS = """\
addROD("known_device_list", { "known_devices": [ { "mac": "00:00:5e:00:53:01", "hostname": "host1", "ip": "192.0.2.100", "activity": 1 } ] });
"""

STATUS_JS = """\
addROD("uptime", '123456');
addROD("get_wan4_ip", '203.0.113.10');
addROD("cgi_wan_ip6_addr", '2001:db8::1');
addCfg("wan_ip4_dns", "e1", "198.51.100.1 198.51.100.2");
"""


class RouterState:
    def __init__(self, username: str = "admin", password: str = "hunter2") -> None:
        self.username = username
        self.password = password
        self.dns_slots: list[dict[str, str]] = [
            {"name": "", "ip": ""} for _ in range(DNS_SLOTS)
        ]
        self.forward_rules: list[dict] = []
        self.port_rules: list[dict] = []
        self.next_rule_id = 1

    def dns_js(self) -> str:
        lines = []
        for i, slot in enumerate(self.dns_slots):
            lines.append(f'addCfg("dns_name{i}", "nm{i}", "{slot["name"]}");')
            lines.append(f'addCfg("dns_ip{i}", "ip{i}", "{slot["ip"]}");')
        return "\n".join(lines) + "\n"

    def forward_js(self) -> str:
        return (
            f'addROD("portforwardings", {json.dumps({"portforwardings": self.forward_rules})});\n'
            f'addROD("upnpportforwardings", [null]);\n'
            f'addROD("readonly_portforwardings", [null]);\n'
            f'addROD("portrules", {json.dumps({"portrules": self.port_rules})});\n'
            f'addROD("schedulerules", null);\n'
            f'addROD("reservePort", null);\n'
        )


def _make_handler(state: RouterState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:
            pass

        def _authed(self) -> bool:
            return f"sysauth={SYSAUTH}" in self.headers.get("Cookie", "")

        def _send(
            self,
            body: str,
            *,
            content_type: str = "text/plain",
            status: int = 200,
            set_cookie: str | None = None,
        ) -> None:
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            if set_cookie:
                self.send_header("Set-Cookie", set_cookie)
            self.end_headers()
            self.wfile.write(data)

        def _form(self) -> dict[str, str]:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode()
            return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/loginStatus.cgi":
                token = APPLY_TOKEN if self._authed() else ""
                self._send(
                    json.dumps({"loginToken": LOGIN_TOKEN, "token": token}),
                    content_type="application/json",
                )
                return

            authed_pages = {
                "/cgi/cgi_status.js": lambda: STATUS_JS,
                "/cgi/cgi_bandwith.js": lambda: BANDWIDTH_JS,
                "/cgi/cgi_owl.js": lambda: OWL_JS,
                "/cgi/cgi_dns_server.js": state.dns_js,
                "/cgi/cgi_firewall_port_forward.js": state.forward_js,
            }
            if path in authed_pages:
                if not self._authed():
                    self._send(LOGIN_PAGE, content_type="text/html")
                    return
                self._send(authed_pages[path](), content_type="text/javascript")
                return

            self._send("not found", status=404)

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            form = self._form()

            if path == "/login.cgi":
                ok = form.get("luci_username") == arc_md5(state.username) and form.get(
                    "luci_password"
                ) == luci_password(state.password, LOGIN_TOKEN)
                if ok:
                    self._send("OK", set_cookie=f"sysauth={SYSAUTH}; Path=/")
                else:
                    self._send("Forbidden", status=403)
                return

            if not self._authed() or form.get("token") != APPLY_TOKEN:
                self._send("Forbidden", status=403)
                return

            if path == "/apply_abstract.cgi":
                for key, value in form.items():
                    m = re.fullmatch(r"(nm|ip)(\d+)", key)
                    if not m:
                        continue
                    field = "name" if m.group(1) == "nm" else "ip"
                    state.dns_slots[int(m.group(2))][field] = value
                self._send("OK")
                return

            if path == "/db.cgi":
                payload = json.loads(form["data"])
                assert payload.get("to") == "forwardrule"
                result: dict = {}
                for entry in payload.get("body", []):
                    if entry.get("type") == "create":
                        rule_id = state.next_rule_id
                        state.next_rule_id += 1
                        state.forward_rules.append(
                            {
                                "id": rule_id,
                                "name": entry["name"],
                                "privateIP": entry["privateIP"],
                                "forward_port": entry["forward_port"],
                                "enable": entry["enable"],
                                "port_rule_id": rule_id,
                            }
                        )
                        state.port_rules.append(
                            {
                                "id": rule_id,
                                "ports": [
                                    {"dest_port": int(p["dest_port"])}
                                    for p in entry.get("ports", [])
                                ],
                            }
                        )
                        result = {"id": rule_id}
                    elif entry.get("type") == "delete":
                        rule_id = int(entry["id"])
                        state.forward_rules = [
                            r for r in state.forward_rules if r["id"] != rule_id
                        ]
                        state.port_rules = [
                            r for r in state.port_rules if r["id"] != rule_id
                        ]
                        result = {"ok": True}
                self._send(json.dumps(result), content_type="application/json")
                return

            self._send("not found", status=404)

    return Handler


class MockRouter:
    def __init__(self, state: RouterState | None = None) -> None:
        self.state = state or RouterState()
        self._server = ThreadingHTTPServer(
            ("127.0.0.1", 0), _make_handler(self.state)
        )
        self._thread = threading.Thread(
            target=lambda: self._server.serve_forever(poll_interval=0.01), daemon=True
        )

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
