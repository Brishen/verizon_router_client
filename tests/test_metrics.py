import pytest
pytest.importorskip("prometheus_client")
from prometheus_client import REGISTRY
from verizon_router_client.metrics import VerizonRouterCollector
from verizon_router_client.config import RouterSettings

def test_collector_registration(router_target):
    client = router_target.make_client()
    if router_target.logged_in_client is None:
        client.login("admin", "hunter2")
    else:
        client = router_target.logged_in_client

    # Unregister if already registered to avoid Duplicate Error
    collectors = list(REGISTRY._collector_to_names.keys())
    for c in collectors:
        if isinstance(c, VerizonRouterCollector):
            REGISTRY.unregister(c)

    collector = VerizonRouterCollector(client, prefix="test_router")
    REGISTRY.register(collector)

    # Check that metrics are collected
    # Uptime metric
    metric_names = [m.name for m in REGISTRY.collect()]
    assert "test_router_uptime_seconds" in metric_names

    # Connected devices
    assert "test_router_connected_devices_count" in metric_names

    # WAN / Status might not have everything in mock, but check what we can.
    # Host bandwidth
    assert "test_router_host_tx_bytes" in metric_names
    assert "test_router_host_rx_bytes" in metric_names
