# verizon-router-client

Python client for Verizon Fios router APIs (focused on the CR1000A web UI endpoints).

## Features

- Login/token helpers for the web UI.
- Fetch status details (uptime, WAN IPs, DNS servers).
- Read/write local DNS entries.
- Read/add/remove port forwarding rules.
- Parse known device lists.

## Install

Local editable install:

```bash
pip install -e .
```

Or with uv:

```bash
uv pip install -e .
```

## Quickstart

```python
from verizon_router_client.cr1000a import VerizonRouterClient

client = VerizonRouterClient(
    base_url="https://192.168.1.1",
    # The router uses a hostname-bound TLS cert; this adapter handles it.
    tls_hostname="mynetworksettings.com",
)

client.login("admin", "your-password")

print(client.get_uptime_seconds())
print(client.get_wan_ipv4())
print(client.get_wan_ipv6())
```

## DNS entries

```python
from verizon_router_client.cr1000a import VerizonRouterClient

client = VerizonRouterClient(
    base_url="https://192.168.1.1",
    # The router uses a hostname-bound TLS cert; this adapter handles it.
    tls_hostname="mynetworksettings.com",
)
client.login("admin", "your-password")

print(client.get_dns_entries_v4())
slot = client.add_dns_ipv4("nas", "192.168.1.10")
client.clear_dns_ipv4_slot(slot)
```

## Port forwarding

```python
from verizon_router_client.cr1000a import VerizonRouterClient

client = VerizonRouterClient(
    base_url="https://192.168.1.1",
    # The router uses a hostname-bound TLS cert; this adapter handles it.
    tls_hostname="mynetworksettings.com",
)
client.login("admin", "your-password")

rule_id = client.add_port_forward(
    name="ssh",
    private_ip="192.168.1.20",
    forward_port=22,
    dest_port=22,
)

client.remove_port_forward(rule_id=rule_id)
```

## Known devices

```python
from verizon_router_client.cr1000a import VerizonRouterClient

client = VerizonRouterClient(
    base_url="https://192.168.1.1",
    # The router uses a hostname-bound TLS cert; this adapter handles it.
    tls_hostname="mynetworksettings.com",
)
devices = client.fetch_known_devices()
```

If you are not already logged in, pass a `sysauth` cookie value:

```python
from verizon_router_client.cr1000a import VerizonRouterClient

client = VerizonRouterClient(
    base_url="https://192.168.1.1",
    # The router uses a hostname-bound TLS cert; this adapter handles it.
    tls_hostname="mynetworksettings.com",
)
devices = client.fetch_known_devices(sysauth_cookie_value="...")
```

## TLS notes

By default the client uses the bundled Verizon Fios root CA (`cert/Verizon Fios Root CA.pem`)
and sets the TLS SNI/Host header to `mynetworksettings.com` when the base URL is an IP.
If your router uses different TLS settings, override `verify_tls` or `tls_hostname`.

## Development

- Python: 3.9+
- Runtime dependency: `requests`

## Disclaimer

This project is not affiliated with Verizon. Use at your own risk.
