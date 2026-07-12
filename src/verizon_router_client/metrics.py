import time
import logging
from typing import Any

from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from prometheus_client import start_http_server, push_to_gateway, CollectorRegistry, REGISTRY

from .cr1000a import VerizonRouterClient
from .config import RouterSettings

logger = logging.getLogger(__name__)

class VerizonRouterCollector:
    """
    A Prometheus custom collector that fetches metrics from the Verizon Router.
    """
    def __init__(self, client: VerizonRouterClient, prefix: str = "verizon_router"):
        self.client = client
        self.prefix = prefix

    def collect(self):
        prefix = self.prefix

        # Uptime
        try:
            uptime = self.client.get_uptime_seconds()
            g_uptime = GaugeMetricFamily(
                f"{prefix}_uptime_seconds",
                "Router uptime in seconds",
                value=uptime
            )
            yield g_uptime
        except Exception as e:
            logger.error("Failed to fetch uptime: %s", e)

        # Status and WAN metrics
        try:
            rod, cfg = self.client.fetch_status()

            if "signal_strength" in rod:
                val = float(rod["signal_strength"])
                yield GaugeMetricFamily(f"{prefix}_signal_strength_dbm", "Signal strength in dBm", value=val)
            if "signal_quality" in rod:
                val = float(rod["signal_quality"])
                yield GaugeMetricFamily(f"{prefix}_signal_quality_pct", "Signal quality percentage", value=val)

            if "wan_tx_bytes" in rod:
                val = float(rod["wan_tx_bytes"])
                yield CounterMetricFamily(f"{prefix}_wan_tx_bytes_total", "WAN Transmitted bytes", value=val)
            if "wan_rx_bytes" in rod:
                val = float(rod["wan_rx_bytes"])
                yield CounterMetricFamily(f"{prefix}_wan_rx_bytes_total", "WAN Received bytes", value=val)
            if "wan_tx_errors" in rod:
                val = float(rod["wan_tx_errors"])
                yield CounterMetricFamily(f"{prefix}_wan_tx_errors_total", "WAN Transmit errors", value=val)
            if "wan_rx_errors" in rod:
                val = float(rod["wan_rx_errors"])
                yield CounterMetricFamily(f"{prefix}_wan_rx_errors_total", "WAN Receive errors", value=val)

            if "ping_latency" in rod:
                val = float(rod["ping_latency"])
                yield GaugeMetricFamily(f"{prefix}_ping_latency_ms", "Ping latency in ms", value=val)

        except Exception as e:
            logger.error("Failed to fetch status metrics: %s", e)

        # Bandwidth metrics
        try:
            rod = self.client.fetch_bandwidth()

            # The firmware payload contains get_history_rates, hosts_trafstat etc.
            # We can expose host traffic via a labeled metric
            trafstat = rod.get("hosts_trafstat", {})

            c_host_tx = CounterMetricFamily(f"{prefix}_host_tx_bytes_total", "Host Transmitted bytes", labels=["mac"])
            c_host_rx = CounterMetricFamily(f"{prefix}_host_rx_bytes_total", "Host Received bytes", labels=["mac"])

            if "3600" in trafstat:
                for mac, stats in trafstat["3600"].items():
                    c_host_tx.add_metric([mac], float(stats.get("bytes_tx", 0)))
                    c_host_rx.add_metric([mac], float(stats.get("bytes_rx", 0)))

            yield c_host_tx
            yield c_host_rx

            if "data_usage_bytes" in rod:
                val = float(rod["data_usage_bytes"])
                yield CounterMetricFamily(f"{prefix}_data_usage_bytes_total", "Total data usage in bytes", value=val)

        except Exception as e:
            logger.error("Failed to fetch bandwidth metrics: %s", e)

        # Connected devices
        try:
            devices = self.client.fetch_known_devices()
            active_devices = [d for d in devices if d.get("activity")]
            yield GaugeMetricFamily(
                f"{prefix}_connected_devices_count",
                "Number of connected devices",
                value=len(active_devices)
            )
        except Exception as e:
            logger.error("Failed to fetch connected devices: %s", e)


def start_metrics_server(client: VerizonRouterClient, settings: RouterSettings):
    collector = VerizonRouterCollector(client, prefix=settings.metric_prefix)
    REGISTRY.register(collector)

    if settings.enable_metrics:
        logger.info("Starting metrics server on %s:%d", settings.metrics_address, settings.metrics_port)
        start_http_server(settings.metrics_port, addr=settings.metrics_address)

    if settings.pushgateway_url:
        logger.info("Pushing metrics to %s every %s seconds", settings.pushgateway_url, settings.push_interval)
        while True:
            try:
                push_to_gateway(
                    settings.pushgateway_url,
                    job=settings.metric_prefix,
                    registry=REGISTRY
                )
            except Exception as e:
                logger.error("Failed to push metrics to pushgateway: %s", e)
            time.sleep(settings.push_interval)
    else:
        # Just keep main thread alive if only serving http
        if settings.enable_metrics:
            while True:
                time.sleep(1)
