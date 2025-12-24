from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
import urllib3

_DEFAULT_CA_CERT = (
    Path(__file__).resolve().parent / "cert" / "Verizon Fios Root CA.pem"
)


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class HostHeaderSSLAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, tls_hostname: str, **kwargs: Any) -> None:
        self._tls_hostname = tls_hostname
        super().__init__(**kwargs)

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any
    ) -> None:
        pool_kwargs["assert_hostname"] = self._tls_hostname
        pool_kwargs["server_hostname"] = self._tls_hostname
        self.poolmanager = urllib3.PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs
        )

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> urllib3.ProxyManager:
        proxy_kwargs["assert_hostname"] = self._tls_hostname
        proxy_kwargs["server_hostname"] = self._tls_hostname
        return super().proxy_manager_for(proxy, **proxy_kwargs)

def _js_8bit_bytes(s: str) -> bytes:
    # Matches the JS code path that effectively uses charCodeAt(...) & 0xFF.
    return bytes((ord(ch) & 0xFF) for ch in s)


def arc_md5(s: str) -> str:
    """
    JS ArcMD5(s):
      md5_hex = md5(js_8bit_bytes(s)).hexdigest()  # lowercase hex
      return sha512(md5_hex as ASCII).hexdigest()  # lowercase hex
    """
    md5_hex = hashlib.md5(_js_8bit_bytes(s)).hexdigest()
    return hashlib.sha512(md5_hex.encode("ascii")).hexdigest()


def luci_username(username: str) -> str:
    return arc_md5(username)


def luci_password(password: str, luci_token: str) -> str:
    if not luci_token:
        return arc_md5(password)
    material = (luci_token + arc_md5(password)).encode("ascii")
    return hashlib.sha512(material).hexdigest()


_ADD_CFG_RE = re.compile(
    r'addCfg\("(?P<key>[^"]+)",\s*"(?P<enc>[^"]*)",\s*"(?P<val>[^"]*)"\);'
)
_KEY_WITH_INDEX_RE = re.compile(r"^(?P<prefix>.*?)(?P<idx>\d+)$")

_ADD_ROD_RE = re.compile(
    r'addROD\("(?P<key>[^"]+)",\s*(?P<val>.*?)\);\s*', re.DOTALL
)


def _strip_wrapping_quotes(s: str) -> str:
    out = s.strip()
    # Some firmwares double-wrap values, so strip at most twice.
    for _ in range(2):
        if len(out) >= 2 and ((out[0] == out[-1] == '"') or (out[0] == out[-1] == "'")):
            out = out[1:-1].strip()
        else:
            break
    return out


def _parse_js_literal(s: str) -> Any:
    v = s.strip()
    v = re.sub(r"\bnull\b", "None", v)
    v = re.sub(r"\btrue\b", "True", v)
    v = re.sub(r"\bfalse\b", "False", v)
    v = v.replace(r"\/", "/")

    try:
        parsed = ast.literal_eval(v)
    except Exception:
        # Raw fallback; still normalize obvious wrapping quotes.
        return _strip_wrapping_quotes(v)

    if isinstance(parsed, str):
        return _strip_wrapping_quotes(parsed)
    return parsed


@dataclass(frozen=True, slots=True)
class CfgEntry:
    key: str
    enc_name: str  # obfuscated field name used in apply_abstract.cgi
    val: str  # plaintext value shown in the UI


@dataclass(slots=True)
class VerizonRouterClient:
    base_url: str = "https://192.168.1.1"
    verify_tls: bool | str = str(_DEFAULT_CA_CERT)
    tls_hostname: str | None = None
    timeout_s: float = 10.0
    session: requests.Session | None = None

    def __post_init__(self) -> None:
        if self.session is None:
            self.session = requests.Session()
        if self.tls_hostname is None:
            host = urlparse(self.base_url).hostname
            if host and _is_ip_host(host):
                self.tls_hostname = "mynetworksettings.com"
        if self.tls_hostname:
            self.session.mount("https://", HostHeaderSSLAdapter(self.tls_hostname))

    def _request_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"Referer": f"{self.base_url.rstrip('/')}/"}
        if self.tls_hostname:
            headers["Host"] = self.tls_hostname
        if extra:
            headers.update(extra)
        return headers

    def get_login_token(self) -> str:
        data = self.login_status()
        token = data.get("loginToken")
        if not isinstance(token, str) or len(token) != 32:
            raise RuntimeError(f"Missing/invalid loginToken in loginStatus: {data}")
        return token.lower()

    def login(
        self,
        username: str,
        password: str,
        *,
        view: str = "Mobile",
        keep_login: bool = False,
    ) -> requests.Response:
        login_token = self.get_login_token()

        payload = {
            "luci_username": luci_username(username),
            "luci_password": luci_password(password, login_token),
            "luci_view": view,
            "luci_token": login_token,
            "luci_keep_login": "1" if keep_login else "0",
        }

        url = f"{self.base_url.rstrip('/')}/login.cgi"
        r = self.session.post(
            url,
            data=payload,  # form-encoded
            timeout=self.timeout_s,
            verify=self.verify_tls,
            headers=self._request_headers(
                {"Content-Type": "application/x-www-form-urlencoded"}
            ),
        )
        return r

    def get_dns_cfg(self) -> dict[str, str]:
        """
        Fetch /cgi/cgi_dns_server.js and return plaintext values keyed by addCfg key.
        """
        text = self._get("/cgi/cgi_dns_server.js").text
        cfg_entries = self._parse_addcfg(text)
        cfg = {key: entry.val for key, entry in cfg_entries.items()}
        if not cfg:
            # Often indicates you were served a login page / redirect JS instead of cfg JS.
            raise RuntimeError(
                "No addCfg() entries found in /cgi/cgi_dns_server.js response."
            )
        return cfg

    @staticmethod
    def _indexed(prefix: str, cfg: dict[str, str]) -> dict[int, str]:
        out: dict[int, str] = {}
        for k, v in cfg.items():
            m = _KEY_WITH_INDEX_RE.match(k)
            if not m:
                continue
            if m.group("prefix") != prefix:
                continue
            out[int(m.group("idx"))] = v
        return out

    def get_dns_entries_v4(self) -> list[dict[str, Any]]:
        """
        Returns rows like:
          {"idx": 0, "name": "example-host", "ip": "192.168.1.2"}
        Only returns indices where either name or ip is non-empty.
        """
        cfg = self.get_dns_cfg()
        ips = self._indexed("dns_ip", cfg)
        names = self._indexed("dns_name", cfg)

        rows: list[dict[str, Any]] = []
        for idx in sorted(set(ips) | set(names)):
            ip = ips.get(idx, "") or ""
            name = names.get(idx, "") or ""
            if ip or name:
                rows.append({"idx": idx, "name": name, "ip": ip})
        return rows

    def get_dns_entries_v6(self) -> list[dict[str, Any]]:
        cfg = self.get_dns_cfg()
        ips = self._indexed("dns_ipv6_ip", cfg)
        names = self._indexed("dns_ipv6_name", cfg)

        rows: list[dict[str, Any]] = []
        for idx in sorted(set(ips) | set(names)):
            ip = ips.get(idx, "") or ""
            name = names.get(idx, "") or ""
            if ip or name:
                rows.append({"idx": idx, "name": name, "ip": ip})
        return rows

    def _url(self, path: str) -> str:
        return f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _get(self, path: str) -> requests.Response:
        r = self.session.get(
            self._url(path),
            timeout=self.timeout_s,
            verify=self.verify_tls,
            headers=self._request_headers(),
        )
        r.raise_for_status()
        return r

    @staticmethod
    def _parse_addcfg(text: str) -> dict[str, CfgEntry]:
        cfg: dict[str, CfgEntry] = {}
        for m in _ADD_CFG_RE.finditer(text):
            key = m.group("key")
            cfg[key] = CfgEntry(key=key, enc_name=m.group("enc"), val=m.group("val"))
        return cfg

    @staticmethod
    def _parse_addrod(text: str) -> dict[str, Any]:
        rod: dict[str, Any] = {}
        for m in _ADD_ROD_RE.finditer(text):
            key = m.group("key")
            rod[key] = _parse_js_literal(m.group("val"))
        return rod

    def get_uptime_seconds(self) -> int:
        rod, _cfg = self.fetch_status()
        uptime = rod.get("uptime")
        if isinstance(uptime, str) and uptime.isdigit():
            return int(uptime)
        if isinstance(uptime, int):
            return uptime
        raise RuntimeError(f"Unexpected uptime value: {uptime!r}")

    def get_wan_ipv4(self) -> str | None:
        rod, _cfg = self.fetch_status()
        v = rod.get("get_wan4_ip")
        return v if isinstance(v, str) and v else None

    def get_wan_ipv6(self) -> str | None:
        rod, _cfg = self.fetch_status()
        v = rod.get("cgi_wan_ip6_addr")
        return v if isinstance(v, str) and v else None

    def get_wan_dns_servers(self) -> list[str]:
        _rod, cfg = self.fetch_status()
        v = cfg.get("wan_ip4_dns")
        if not v or not v.val.strip():
            return []
        return [x for x in v.val.split() if x]

    def fetch_status(self) -> tuple[dict[str, Any], dict[str, CfgEntry]]:
        """
        GET /cgi/cgi_status.js and parse:
          - addROD(...) into a dict[str, Any]
          - addCfg(...) into a dict[str, CfgEntry]
        """
        text = self._get("/cgi/cgi_status.js").text
        rod = self._parse_addrod(text)
        cfg = self._parse_addcfg(text)
        if not rod and not cfg:
            raise RuntimeError("No addROD/addCfg entries found in /cgi/cgi_status.js")
        return rod, cfg

    def fetch_port_forwarding(self) -> dict[str, Any]:
        """
        GET /cgi/cgi_firewall_port_forward.js and parse addROD(...) payloads.
        """
        text = self._get("/cgi/cgi_firewall_port_forward.js").text
        rod = self._parse_addrod(text)
        if not rod:
            raise RuntimeError(
                "No addROD() entries found in /cgi/cgi_firewall_port_forward.js"
            )
        return rod

    def get_port_forwarding_settings(self) -> dict[str, Any]:
        """
        Returns a normalized view of the port forwarding payload, with null entries removed.
        """
        rod = self.fetch_port_forwarding()

        portforwardings = rod.get("portforwardings")
        if not isinstance(portforwardings, dict):
            raise RuntimeError(
                f"Unexpected portforwardings payload: {type(portforwardings)}"
            )
        entries = portforwardings.get("portforwardings")
        if not isinstance(entries, list):
            raise RuntimeError(
                f"Unexpected portforwardings list: {type(entries)}"
            )

        upnp = rod.get("upnpportforwardings")
        if upnp is None:
            upnp_entries: list[Any] = []
        elif isinstance(upnp, list):
            upnp_entries = [entry for entry in upnp if entry is not None]
        else:
            raise RuntimeError(
                f"Unexpected upnpportforwardings payload: {type(upnp)}"
            )

        readonly = rod.get("readonly_portforwardings")
        if readonly is None:
            readonly_entries: list[Any] = []
        elif isinstance(readonly, list):
            readonly_entries = [entry for entry in readonly if entry is not None]
        else:
            raise RuntimeError(
                f"Unexpected readonly_portforwardings payload: {type(readonly)}"
            )

        return {
            "portforwardings": entries,
            "upnpportforwardings": upnp_entries,
            "readonly_portforwardings": readonly_entries,
            "portrules": rod.get("portrules"),
            "schedulerules": rod.get("schedulerules"),
            "reservePort": rod.get("reservePort"),
        }

    def _post_form(self, path: str, data: dict[str, str]) -> requests.Response:
        r = self.session.post(
            self._url(path),
            data=data,
            timeout=self.timeout_s,
            verify=self.verify_tls,
            headers=self._request_headers(
                {"Content-Type": "application/x-www-form-urlencoded"}
            ),
        )
        r.raise_for_status()
        return r

    def _post_db(self, payload: dict[str, Any], *, token: str | None = None) -> Any:
        if token is None:
            token = self.get_apply_token()
        data = {"data": json.dumps(payload), "token": token}
        r = self._post_form("/db.cgi", data)
        try:
            return r.json()
        except ValueError:
            return r.text

    # ---- tokens / auth ----
    def login_status(self) -> dict[str, Any]:
        data = self._get("/loginStatus.cgi").json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Unexpected loginStatus.cgi JSON: {type(data)}")
        return data

    def get_apply_token(self) -> str:
        """
        Token used in apply_abstract.cgi. In many firmwares it becomes non-empty after login.
        """
        tok = self.login_status().get("token")
        if isinstance(tok, str) and tok:
            return tok
        raise RuntimeError(
            "No non-empty apply token in loginStatus.cgi. "
            "After login, check loginStatus.cgi again; if still empty, the token is likely loaded from another endpoint/page."
        )

    def add_port_forward(
        self,
        *,
        name: str,
        private_ip: str,
        forward_port: int | str,
        dest_port: int | str,
        enable: bool = True,
        schedule_rule_id: int | str = 0,
        port_type: int = 8,
        source_type: int = 0,
        source_port: str = "",
        dest_type: int = 1,
        token: str | None = None,
    ) -> int:
        """
        Create a port forwarding rule via /db.cgi and return the new rule id.
        """
        payload = {
            "type": "edit",
            "to": "forwardrule",
            "body": [
                {
                    "type": "create",
                    "enable": "1" if enable else "0",
                    "name": name,
                    "privateIP": private_ip,
                    "forward_port": str(forward_port),
                    "schedule_rule_id": str(schedule_rule_id),
                    "ports": [
                        {
                            "type": port_type,
                            "source_type": source_type,
                            "source_port": source_port,
                            "dest_type": dest_type,
                            "dest_port": str(dest_port),
                        }
                    ],
                }
            ],
        }
        response = self._post_db(payload, token=token)
        rule_id = self._extract_rule_id_from_response(response)
        if rule_id is not None:
            return rule_id
        rule_id = self._lookup_port_forward_id(
            name=name,
            private_ip=private_ip,
            forward_port=forward_port,
            dest_port=dest_port,
        )
        if rule_id is None:
            raise RuntimeError(
                f"Port forward created but rule id not found. Response: {response!r}"
            )
        return rule_id

    def remove_port_forward(
        self,
        *,
        rule_id: int | str,
        token: str | None = None,
    ) -> Any:
        """
        Remove a port forwarding rule via /db.cgi.
        """
        payload = {
            "type": "edit",
            "to": "forwardrule",
            "body": [{"type": "delete", "id": str(rule_id)}],
        }
        return self._post_db(payload, token=token)

    @staticmethod
    def _extract_rule_id_from_response(response: Any) -> int | None:
        if isinstance(response, dict):
            for key in ("id", "rule_id", "forward_rule_id"):
                value = response.get(key)
                if isinstance(value, int):
                    return value
                if isinstance(value, str) and value.isdigit():
                    return int(value)
            body = response.get("body")
            if isinstance(body, list) and body:
                first = body[0]
                if isinstance(first, dict):
                    value = first.get("id")
                    if isinstance(value, int):
                        return value
                    if isinstance(value, str) and value.isdigit():
                        return int(value)
        return None

    def _lookup_port_forward_id(
        self,
        *,
        name: str,
        private_ip: str,
        forward_port: int | str,
        dest_port: int | str,
    ) -> int | None:
        settings = self.get_port_forwarding_settings()
        entries = settings.get("portforwardings")
        if not isinstance(entries, list):
            return None

        port_rule_ports: dict[int, set[str]] = {}
        portrules = settings.get("portrules")
        if isinstance(portrules, dict):
            rules = portrules.get("portrules")
            if isinstance(rules, list):
                for rule in rules:
                    if not isinstance(rule, dict):
                        continue
                    rule_id = rule.get("id")
                    ports = rule.get("ports")
                    if not isinstance(rule_id, int) or not isinstance(ports, list):
                        continue
                    dest_ports = {
                        str(port.get("dest_port"))
                        for port in ports
                        if isinstance(port, dict) and "dest_port" in port
                    }
                    port_rule_ports[rule_id] = dest_ports

        matches: list[int] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("name") != name:
                continue
            if entry.get("privateIP") != private_ip:
                continue
            if str(entry.get("forward_port")) != str(forward_port):
                continue
            port_rule_id = entry.get("port_rule_id")
            if isinstance(port_rule_id, int):
                dest_ports = port_rule_ports.get(port_rule_id)
                if dest_ports and str(dest_port) not in dest_ports:
                    continue
            entry_id = entry.get("id")
            if isinstance(entry_id, int):
                matches.append(entry_id)

        if not matches:
            return None
        return max(matches)

    # ---- cfg parsing ----
    def fetch_dns_cfg(self) -> dict[str, CfgEntry]:
        """
        GET /cgi/cgi_dns_server.js and parse addCfg() into a mapping:
        logical key -> (obfuscated field name, plaintext value)
        """
        text = self._get("/cgi/cgi_dns_server.js").text
        cfg = self._parse_addcfg(text)
        if not cfg:
            raise RuntimeError("No addCfg() entries found in /cgi/cgi_dns_server.js")
        return cfg

    # ---- read helpers ----
    @staticmethod
    def list_dns_ipv4(
        cfg: dict[str, CfgEntry], *, max_n: int = 64
    ) -> list[tuple[int, str, str]]:
        """
        Returns [(idx, hostname, ip), ...] for non-empty hostnames.
        """
        out: list[tuple[int, str, str]] = []
        for i in range(max_n):
            name = cfg.get(f"dns_name{i}")
            ip = cfg.get(f"dns_ip{i}")
            if not name or not ip:
                continue
            if name.val.strip():
                out.append((i, name.val, ip.val))
        return out

    # ---- write helpers ----
    def _apply_dnsmasq_reload(self, field_updates: dict[str, str]) -> None:
        token = self.get_apply_token()
        data = {"token": token, "action": "dnsmasq_reload"}
        data.update(field_updates)
        self._post_form("/apply_abstract.cgi", data)

    def add_dns_ipv4(self, hostname: str, ip: str) -> int:
        cfg = self.fetch_dns_cfg()

        slot = None
        for i in range(64):
            name = cfg.get(f"dns_name{i}")
            if name and not name.val.strip():
                slot = i
                break
        if slot is None:
            raise RuntimeError("No empty dns_nameN slots available (0..63).")

        name_entry = cfg.get(f"dns_name{slot}")
        ip_entry = cfg.get(f"dns_ip{slot}")
        if not name_entry or not ip_entry:
            raise RuntimeError(f"Missing cfg entries for slot {slot}.")

        self._apply_dnsmasq_reload(
            {
                ip_entry.enc_name: ip,
                name_entry.enc_name: hostname,
            }
        )
        return slot

    # ---- remove / clear helpers ----
    def clear_dns_ipv4_slot(self, slot: int) -> None:
        if not (0 <= slot < 64):
            raise ValueError("slot must be in [0, 63].")
        cfg = self.fetch_dns_cfg()

        name_entry = cfg.get(f"dns_name{slot}")
        ip_entry = cfg.get(f"dns_ip{slot}")
        if not name_entry or not ip_entry:
            raise RuntimeError(f"Missing cfg entries for slot {slot}.")

        # Clearing both fields matches the UI’s “edit then apply” model.
        self._apply_dnsmasq_reload({ip_entry.enc_name: "", name_entry.enc_name: ""})

    def clear_dns_ipv6_slot(self, slot: int) -> None:
        if not (0 <= slot < 64):
            raise ValueError("slot must be in [0, 63].")
        cfg = self.fetch_dns_cfg()

        name_entry = cfg.get(f"dns_ipv6_name{slot}")
        ip_entry = cfg.get(f"dns_ipv6_ip{slot}")
        if not name_entry or not ip_entry:
            raise RuntimeError(f"Missing cfg entries for slot {slot}.")

        self._apply_dnsmasq_reload({ip_entry.enc_name: "", name_entry.enc_name: ""})

    def remove_dns_ipv4_by_hostname(
        self, hostname: str, *, remove_all: bool = False
    ) -> list[int]:
        cfg = self.fetch_dns_cfg()
        matches = [
            idx for idx, host, _ip in self.list_dns_ipv4(cfg) if host == hostname
        ]
        if not matches:
            return []
        removed: list[int] = []
        for idx in matches if remove_all else matches[:1]:
            self.clear_dns_ipv4_slot(idx)
            removed.append(idx)
        return removed

    def remove_dns_ipv4_by_ip(self, ip: str, *, remove_all: bool = False) -> list[int]:
        cfg = self.fetch_dns_cfg()
        matches = [idx for idx, _host, addr in self.list_dns_ipv4(cfg) if addr == ip]
        if not matches:
            return []
        removed: list[int] = []
        for idx in matches if remove_all else matches[:1]:
            self.clear_dns_ipv4_slot(idx)
            removed.append(idx)
        return removed

    def remove_dns_ipv6_by_hostname(
        self, hostname: str, *, remove_all: bool = False
    ) -> list[int]:
        cfg = self.fetch_dns_cfg()
        matches = [
            idx for idx, host, _ip in self.list_dns_ipv6(cfg) if host == hostname
        ]
        if not matches:
            return []
        removed: list[int] = []
        for idx in matches if remove_all else matches[:1]:
            self.clear_dns_ipv6_slot(idx)
            removed.append(idx)
        return removed

    def remove_dns_ipv6_by_ip(self, ip: str, *, remove_all: bool = False) -> list[int]:
        cfg = self.fetch_dns_cfg()
        matches = [idx for idx, _host, addr in self.list_dns_ipv6(cfg) if addr == ip]
        if not matches:
            return []
        removed: list[int] = []
        for idx in matches if remove_all else matches[:1]:
            self.clear_dns_ipv6_slot(idx)
            removed.append(idx)
        return removed

    @staticmethod
    def _extract_js_object_argument(src: str, call_prefix: str) -> str:
        """
        Extract the {...} argument from a JS call like:
            addROD("known_device_list", {...});
        using brace matching (safe against nested objects/arrays).
        """
        i = src.find(call_prefix)
        if i < 0:
            raise ValueError(f"Call prefix not found: {call_prefix!r}")

        j = src.find("{", i)
        if j < 0:
            raise ValueError("No '{' found after call prefix.")

        depth = 0
        in_str = False
        esc = False

        for k in range(j, len(src)):
            ch = src[k]

            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue

            if ch == '"':
                in_str = True
                continue

            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return src[j : k + 1]

        raise ValueError("Unbalanced braces while extracting object literal.")

    @staticmethod
    def parse_known_devices(js_text: str) -> list[dict[str, Any]]:
        obj_text = VerizonRouterClient._extract_js_object_argument(
            js_text,
            'addROD("known_device_list",',
        )
        payload = json.loads(obj_text)
        devices = payload.get("known_devices", [])
        if isinstance(devices, list):
            return devices
        raise RuntimeError(f"Unexpected known_devices type: {type(devices)}")

    def fetch_known_devices(
        self, *, sysauth_cookie_value: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Fetch /cgi/cgi_owl.js and parse known device list.

        If sysauth_cookie_value is not provided, this relies on the current session
        already having a valid 'sysauth' cookie.
        """
        url = self._url("/cgi/cgi_owl.js")
        headers = self._request_headers({"Accept": "application/json, text/plain, */*"})
        cookies = {"sysauth": sysauth_cookie_value} if sysauth_cookie_value else None

        r = self.session.get(
            url,
            headers=headers,
            cookies=cookies,
            timeout=self.timeout_s,
            verify=self.verify_tls,
        )
        r.raise_for_status()
        return self.parse_known_devices(r.text)
