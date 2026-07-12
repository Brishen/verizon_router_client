from __future__ import annotations

import json
from typing import Any

import click

from .config import RouterSettings, connect
from .cr1000a import VerizonRouterClient


def _echo_json(data: Any) -> None:
    click.echo(json.dumps(data, indent=2))


def _client(ctx: click.Context) -> VerizonRouterClient:
    settings: RouterSettings = ctx.obj
    if not settings.password.get_secret_value():
        raise click.UsageError(
            "No router password configured. Use --password, VZ_ROUTER_PASSWORD, or .env."
        )
    return connect(settings)


@click.group()
@click.option("--base-url", default=None, help="Router URL, e.g. https://192.168.1.1")
@click.option("--username", default=None, help="Router admin username.")
@click.option("--password", default=None, help="Router admin password.")
@click.option(
    "--verify-tls",
    default=None,
    help="true/false or a CA bundle path. Defaults to the bundled Fios root CA.",
)
@click.option("--tls-hostname", default=None, help="SNI hostname for TLS verification.")
@click.option("--timeout", type=float, default=None, help="Request timeout in seconds.")
@click.pass_context
def cli(
    ctx: click.Context,
    base_url: str | None,
    username: str | None,
    password: str | None,
    verify_tls: str | None,
    tls_hostname: str | None,
    timeout: float | None,
) -> None:
    """CLI for Verizon Fios CR1000A routers.

    Options fall back to VZ_ROUTER_* environment variables and a .env file.
    """
    overrides: dict[str, Any] = {
        "base_url": base_url,
        "username": username,
        "password": password,
        "verify_tls": verify_tls,
        "tls_hostname": tls_hostname,
        "timeout_s": timeout,
    }
    overrides = {k: v for k, v in overrides.items() if v is not None}
    ctx.obj = RouterSettings(**overrides)


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show uptime, WAN addresses, and WAN DNS servers."""
    client = _client(ctx)
    _echo_json(
        {
            "uptime_seconds": client.get_uptime_seconds(),
            "wan_ipv4": client.get_wan_ipv4(),
            "wan_ipv6": client.get_wan_ipv6(),
            "wan_dns_servers": client.get_wan_dns_servers(),
        }
    )


@cli.command()
@click.option("--active", is_flag=True, help="Only show currently active devices.")
@click.option("--full", is_flag=True, help="Show all fields instead of a summary.")
@click.pass_context
def devices(ctx: click.Context, active: bool, full: bool) -> None:
    """List known devices."""
    client = _client(ctx)
    rows = client.fetch_known_devices()
    if active:
        rows = [d for d in rows if d.get("activity")]
    if not full:
        rows = [
            {
                "mac": d.get("mac"),
                "name": d.get("name") or d.get("hostname"),
                "ip": d.get("ip"),
                "active": bool(d.get("activity")),
                "last_active": d.get("time_last_active"),
            }
            for d in rows
        ]
    _echo_json(rows)


@cli.group()
def bandwidth() -> None:
    """Bandwidth and traffic statistics."""


@bandwidth.command("history")
@click.pass_context
def bandwidth_history(ctx: click.Context) -> None:
    """Show the router's bandwidth history rate series."""
    client = _client(ctx)
    _echo_json(client.get_bandwidth_history_rates())


@bandwidth.command("hosts")
@click.option(
    "--period",
    type=click.Choice(["3600", "43200", "86400", "604800", "2592000"]),
    default=None,
    help="Only show one aggregation period (seconds).",
)
@click.pass_context
def bandwidth_hosts(ctx: click.Context, period: str | None) -> None:
    """Show per-host traffic statistics."""
    client = _client(ctx)
    stats = client.get_host_traffic_stats()
    if period is not None:
        _echo_json(stats.get(int(period), {}))
    else:
        _echo_json(stats)


@cli.group()
def dns() -> None:
    """Local DNS entries."""


@dns.command("list")
@click.option("--ipv6", is_flag=True, help="List IPv6 entries instead of IPv4.")
@click.pass_context
def dns_list(ctx: click.Context, ipv6: bool) -> None:
    """List local DNS entries."""
    client = _client(ctx)
    rows = client.get_dns_entries_v6() if ipv6 else client.get_dns_entries_v4()
    _echo_json(rows)


@dns.command("add")
@click.argument("hostname")
@click.argument("ip")
@click.pass_context
def dns_add(ctx: click.Context, hostname: str, ip: str) -> None:
    """Add a local IPv4 DNS entry."""
    client = _client(ctx)
    slot = client.add_dns_ipv4(hostname, ip)
    click.echo(f"Added {hostname} -> {ip} in slot {slot}")


@dns.command("remove")
@click.argument("value")
@click.option("--by-ip", is_flag=True, help="Match on IP instead of hostname.")
@click.option("--ipv6", is_flag=True, help="Operate on IPv6 entries.")
@click.option("--all", "remove_all", is_flag=True, help="Remove all matches.")
@click.pass_context
def dns_remove(
    ctx: click.Context, value: str, by_ip: bool, ipv6: bool, remove_all: bool
) -> None:
    """Remove local DNS entries matching VALUE (hostname by default)."""
    client = _client(ctx)
    if ipv6:
        remove = (
            client.remove_dns_ipv6_by_ip if by_ip else client.remove_dns_ipv6_by_hostname
        )
    else:
        remove = (
            client.remove_dns_ipv4_by_ip if by_ip else client.remove_dns_ipv4_by_hostname
        )
    removed = remove(value, remove_all=remove_all)
    if not removed:
        raise click.ClickException(f"No DNS entries matched {value!r}.")
    click.echo(f"Removed slot(s): {', '.join(map(str, removed))}")


@cli.group()
def forward() -> None:
    """Port forwarding rules."""


@forward.command("list")
@click.pass_context
def forward_list(ctx: click.Context) -> None:
    """List port forwarding rules."""
    client = _client(ctx)
    _echo_json(client.get_port_forwarding_settings())


@forward.command("add")
@click.option("--name", required=True, help="Rule name.")
@click.option("--private-ip", required=True, help="LAN IP to forward to.")
@click.option("--forward-port", required=True, help="External port.")
@click.option("--dest-port", required=True, help="Internal destination port.")
@click.option("--disabled", is_flag=True, help="Create the rule disabled.")
@click.pass_context
def forward_add(
    ctx: click.Context,
    name: str,
    private_ip: str,
    forward_port: str,
    dest_port: str,
    disabled: bool,
) -> None:
    """Add a port forwarding rule."""
    client = _client(ctx)
    rule_id = client.add_port_forward(
        name=name,
        private_ip=private_ip,
        forward_port=forward_port,
        dest_port=dest_port,
        enable=not disabled,
    )
    click.echo(f"Created rule id {rule_id}")


@forward.command("remove")
@click.argument("rule_id")
@click.pass_context
def forward_remove(ctx: click.Context, rule_id: str) -> None:
    """Remove a port forwarding rule by id."""
    client = _client(ctx)
    client.remove_port_forward(rule_id=rule_id)
    click.echo(f"Removed rule id {rule_id}")


@cli.command()
@click.option("--address", default=None, help="Listen address for the metrics server.")
@click.option("--port", type=int, default=None, help="Listen port for the metrics server.")
@click.option("--pushgateway-url", default=None, help="Prometheus Pushgateway URL.")
@click.option("--push-interval", type=float, default=None, help="Push interval in seconds.")
@click.pass_context
def metrics(
    ctx: click.Context,
    address: str | None,
    port: int | None,
    pushgateway_url: str | None,
    push_interval: float | None,
) -> None:
    """Start the Prometheus metrics exporter or push loop."""
    settings: RouterSettings = ctx.obj
    if address is not None:
        settings.metrics_address = address
    if port is not None:
        settings.metrics_port = port
    if pushgateway_url is not None:
        settings.pushgateway_url = pushgateway_url
    if push_interval is not None:
        settings.push_interval = push_interval

    # To run the metrics server, we implicitly enable metrics if this command is run.
    settings.enable_metrics = True

    client = _client(ctx)
    from .metrics import start_metrics_server
    start_metrics_server(client, settings)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
