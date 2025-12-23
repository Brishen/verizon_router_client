from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
import ast
import json

import requests


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


_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")

_ADD_CFG_RE = re.compile(
    r'addCfg\("(?P<key>[^"]+)",\s*"(?P<enc>[^"]*)",\s*"(?P<val>[^"]*)"\);'
)
_KEY_WITH_INDEX_RE = re.compile(r"^(?P<prefix>.*?)(?P<idx>\d+)$")

_ADD_ROD_RE = re.compile(r'addROD\("(?P<key>[^"]+)",\s*(?P<val>.*?)\);\s*')


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

    try:
        parsed = ast.literal_eval(v)
    except Exception:
        # Raw fallback; still normalize obvious wrapping quotes.
        return _strip_wrapping_quotes(v)

    if isinstance(parsed, str):
        return _strip_wrapping_quotes(parsed)
    return parsed


def _find_hex32(obj: Any) -> str | None:
    """
    Recursively search JSON-ish structures for a 32-hex token.
    This is a heuristic because Verizon firmware variants differ in field names.
    """
    if isinstance(obj, str) and _HEX32.fullmatch(obj):
        return obj
    if isinstance(obj, dict):
        # Prefer obvious names if present
        for k in ("luci_token", "token", "loginToken", "login_token"):
            v = obj.get(k)
            if isinstance(v, str) and _HEX32.fullmatch(v):
                return v
        for v in obj.values():
            found = _find_hex32(v)
            if found:
                return found
    if isinstance(obj, list):
        for v in obj:
            found = _find_hex32(v)
            if found:
                return found
    return None


@dataclass(frozen=True, slots=True)
class CfgEntry:
    key: str
    enc_name: str  # obfuscated field name used in apply_abstract.cgi
    val: str  # plaintext value shown in the UI


@dataclass(slots=True)
class VerizonRouterClient:
    """
    Example base_url: "https://192.168.1.1:10443"
    (matches your fetch() and implies a self-signed cert in many cases)
    """

    base_url: str = "https://192.168.1.1:10443"
    verify_tls: bool = False
    timeout_s: float = 10.0
    session: requests.Session = None

    def __post_init__(self) -> None:
        self.session = requests.Session()

    def login_status(self) -> dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}/loginStatus.cgi"
        r = self.session.get(
            url,
            headers={"Accept": "application/json, text/plain, */*"},
            timeout=self.timeout_s,
            verify=self.verify_tls,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Unexpected loginStatus.cgi JSON type: {type(data)}")
        return data

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
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        return r

    def _get_text(self, path: str) -> str:
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        r = self.session.get(
            url,
            timeout=self.timeout_s,
            verify=self.verify_tls,
            headers={
                "Accept": "application/json, text/plain, */*",
                "Referer": f"{self.base_url.rstrip('/')}/",
            },
        )
        r.raise_for_status()
        return r.text

    def get_dns_cfg(self) -> dict[str, str]:
        """
        Fetch /cgi/cgi_dns_server.js and return plaintext values keyed by addCfg key.
        """
        js = self._get_text("/cgi/cgi_dns_server.js")

        cfg: dict[str, str] = {}
        for m in _ADD_CFG_RE.finditer(js):
            key = m.group("key")
            val = m.group("val")
            cfg[key] = val
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
          {"idx": 0, "name": "truenas-ssd", "ip": "192.168.1.195"}
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
            headers={"Referer": f"{self.base_url.rstrip('/')}/"},
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
        # In your sample, "wan_ip4_dns" is a space-separated string of servers.
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

    def _post_form(self, path: str, data: dict[str, str]) -> requests.Response:
        r = self.session.post(
            self._url(path),
            data=data,
            timeout=self.timeout_s,
            verify=self.verify_tls,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": f"{self.base_url.rstrip('/')}/",
            },
        )
        r.raise_for_status()
        return r

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

    # ---- cfg parsing ----
    def fetch_dns_cfg(self) -> dict[str, CfgEntry]:
        """
        GET /cgi/cgi_dns_server.js and parse addCfg() into a mapping:
        logical key -> (obfuscated field name, plaintext value)
        """
        text = self._get("/cgi/cgi_dns_server.js").text
        cfg: dict[str, CfgEntry] = {}
        for m in _ADD_CFG_RE.finditer(text):
            key = m.group("key")
            cfg[key] = CfgEntry(key=key, enc_name=m.group("enc"), val=m.group("val"))
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
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Referer": f"{self.base_url.rstrip('/')}/",
        }
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
