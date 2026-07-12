# verizon-router-client

Python client for Verizon Fios router APIs (focused on the CR1000A web UI endpoints).

## Features

- Login/token helpers for the web UI.
- Fetch status details (uptime, WAN IPs, DNS servers).
- Read/write local DNS entries.
- Read/add/remove port forwarding rules.
- Parse known device lists.
- Bandwidth history and per-host traffic statistics.
- Settings from environment variables / `.env` (pydantic-settings).
- `vzrouter` command-line interface (click).

## Install

Local editable install:

```bash
pip install -e .
```

Or with uv:

```bash
uv pip install -e .
```

## Configuration

Settings are read from `VZ_ROUTER_*` environment variables and/or a `.env`
file in the working directory (environment variables win). Copy
`.env.example` to `.env` and fill in your values:

```dotenv
VZ_ROUTER_BASE_URL=https://192.168.1.1
VZ_ROUTER_USERNAME=admin
VZ_ROUTER_PASSWORD=your-admin-password
# Optional:
# VZ_ROUTER_VERIFY_TLS=false          # or a path to a CA bundle
# VZ_ROUTER_TLS_HOSTNAME=mynetworksettings.com
# VZ_ROUTER_TIMEOUT_S=10.0
# VZ_ROUTER_ENABLE_METRICS=true
# VZ_ROUTER_METRICS_PORT=9100
```

With that in place, `connect()` builds a client and logs in:

```python
from verizon_router_client import connect

client = connect()
```

You can also construct settings explicitly with
`RouterSettings(base_url=..., password=...)` and pass them to `connect()` or
`VerizonRouterClient.from_settings()`.

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

## Bandwidth and traffic statistics

Parses `/cgi/cgi_bandwith.js` (the endpoint name is misspelled in firmware):

```python
from verizon_router_client import connect

client = connect()

# Bandwidth history rate series (lists of ints, as reported by the router).
history = client.get_bandwidth_history_rates()

# Per-host traffic, keyed by aggregation period in seconds
# (3600, 43200, 86400, 604800, 2592000), then by MAC address.
stats = client.get_host_traffic_stats()
hour = stats[3600]
for mac, counters in hour.items():
    print(mac, counters["bytes_tx"], counters["bytes_rx"])

# Raw addROD payloads (includes known_device_list, fsam_update, ...).
raw = client.fetch_bandwidth()
```

## Command-line interface

Installing the package provides a `vzrouter` command. Connection options fall
back to the same `VZ_ROUTER_*` environment variables / `.env` file, and can be
overridden with flags (`--base-url`, `--username`, `--password`,
`--verify-tls`, `--tls-hostname`, `--timeout`). Structured output is JSON.

```bash
# Status: uptime, WAN IPs, WAN DNS servers
vzrouter status

# Known devices (summary; --full for all fields)
vzrouter devices --active

# Bandwidth
vzrouter bandwidth history
vzrouter bandwidth hosts --period 3600

# Local DNS entries
vzrouter dns list
vzrouter dns add nas 192.168.1.10
vzrouter dns remove nas
vzrouter dns remove 192.168.1.10 --by-ip --all

# Port forwarding
vzrouter forward list
vzrouter forward add --name ssh --private-ip 192.168.1.20 \
  --forward-port 22 --dest-port 22
vzrouter forward remove 12345
```

## Metrics Export (Prometheus)

You can run a Prometheus-compatible metrics server to monitor your router's performance, connected devices, traffic stats, and signal qualities via Grafana:

```bash
vzrouter metrics --address 0.0.0.0 --port 9100
```

To use a Prometheus Pushgateway instead:
```bash
vzrouter metrics --pushgateway-url http://localhost:9091 --push-interval 30.0
```

Sample Prometheus configuration (`prometheus.yml`):
```yaml
scrape_configs:
  - job_name: "verizon_router"
    static_configs:
      - targets: ["localhost:9100"]
```

## TLS notes

By default the client uses the bundled Verizon Fios root CA (`cert/Verizon Fios Root CA.pem`)
and sets the TLS SNI/Host header to `mynetworksettings.com` when the base URL is an IP.
If your router uses different TLS settings, override `verify_tls` or `tls_hostname`.

## Development

- Python: 3.10+
- Runtime dependencies: `requests`, `pydantic-settings`, `click`

## Testing

Run the suite with pytest:

```bash
uv run pytest
```

Unit tests (parsing, auth hashing, settings, CLI) never touch the network.
Integration tests run against a backend selected with `--router`:

```bash
uv run pytest --router=mock   # in-process mock router service
uv run pytest --router=real   # your real router, credentials from .env
uv run pytest                 # auto (default): real if .env has a password,
                              # mock otherwise
```

- **Mock** (`tests/mock_router.py`): an in-process HTTP service emulating the
  CR1000A — hashed-credential login with a `sysauth` cookie, auth-gated
  `cgi/*.js` endpoints, and stateful DNS / port-forwarding mutations. All
  fixture data uses RFC documentation values.
- **Real**: reads credentials from the project `.env` (`--router=real` skips
  if none). Mutating tests create uniquely named entries (`pytest-vzr-*`)
  and remove them afterwards. Tests that need deterministic state or are
  unsafe against real hardware (e.g. repeated failed logins) always run
  against the mock, whichever backend is selected.

Note: the router throttles rapid logins, so real-mode tests share a single
login for the whole session. If the router is still throttling from recent
attempts, the real-backend tests skip with an explanatory message — wait a
few minutes and rerun.

## Kubernetes Operator

The `verizon-router-client` can also be deployed as a Kubernetes operator using [kopf](https://kopf.readthedocs.io/).
The operator manages custom resources for DNS and Port Forwarding.

### Helm

You can easily install the operator using the provided Helm chart.

```bash
# If you don't have an existing secret, you can pass the password directly
helm install verizon-router-operator ./charts/verizon-router-operator \
  --set router.password='YOUR_ROUTER_PASSWORD'

# Or, if you've created a secret named `verizon-router-secret` with the `password` key:
helm install verizon-router-operator ./charts/verizon-router-operator
```

### Setup

First, install the package with operator dependencies:

```bash
pip install -e ".[operator]"
```

Or build and use the provided Docker image:

```bash
docker build -t verizon-router-operator:latest .
```

### Apply CRDs & RBAC

Apply the Custom Resource Definitions (CRDs) and Role-Based Access Control (RBAC):

```bash
kubectl apply -f k8s/crd-fiosdnsrecord.yaml
kubectl apply -f k8s/crd-fiosportforward.yaml
kubectl apply -f k8s/rbac.yaml
```

### Configure Authentication

Create a secret with your router password:

```bash
kubectl create secret generic verizon-router-secret \
  --from-literal=password='YOUR_ROUTER_PASSWORD'
```

Deploy the operator:

```bash
kubectl apply -f k8s/deployment.yaml
```

### Custom Resources

You can now manage your router via standard Kubernetes manifests.

**Add a DNS Record:**

```yaml
apiVersion: network.verizon.com/v1alpha1
kind: FiosDnsRecord
metadata:
  name: nas-entry
spec:
  hostname: nas
  ip: 192.168.1.10
```

**Add a Port Forwarding Rule:**

```yaml
apiVersion: network.verizon.com/v1alpha1
kind: FiosPortForward
metadata:
  name: ssh-forward
spec:
  name: ssh
  private_ip: 192.168.1.20
  forward_port: 22
  dest_port: 22
```

## Disclaimer

This project is not affiliated with Verizon. Use at your own risk.
