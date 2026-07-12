from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

if TYPE_CHECKING:
    from .cr1000a import VerizonRouterClient


class RouterSettings(BaseSettings):
    """
    Router connection settings, loaded from environment variables and/or a
    .env file in the working directory. Environment variables take precedence
    over .env values.

    Example .env:
        VZ_ROUTER_BASE_URL=https://192.168.1.1
        VZ_ROUTER_USERNAME=admin
        VZ_ROUTER_PASSWORD=your-admin-password
    """

    model_config = SettingsConfigDict(
        env_prefix="VZ_ROUTER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    base_url: str = "https://192.168.1.1"
    username: str = "admin"
    password: SecretStr = SecretStr("")
    # Path to a CA bundle, or true/false. None uses the bundled Fios root CA.
    verify_tls: bool | str | None = None
    tls_hostname: str | None = None
    timeout_s: float = 10.0

    # Metrics configuration
    enable_metrics: bool = False
    metrics_address: str = "0.0.0.0"
    metrics_port: int = 9100
    pushgateway_url: str | None = None
    push_interval: float = 30.0
    metric_prefix: str = "verizon_router"

    @field_validator("verify_tls", mode="before")
    @classmethod
    def _coerce_verify_tls(cls, v: object) -> object:
        # Env values are strings; map boolean-looking ones to bool so requests
        # doesn't mistake "false" for a CA bundle path.
        if isinstance(v, str):
            lowered = v.strip().lower()
            if lowered in {"true", "1", "yes", "on"}:
                return True
            if lowered in {"false", "0", "no", "off"}:
                return False
        return v


def connect(settings: RouterSettings | None = None) -> "VerizonRouterClient":
    """
    Build a VerizonRouterClient from settings (env / .env when omitted) and log in.
    """
    from .cr1000a import VerizonRouterClient

    if settings is None:
        settings = RouterSettings()
    client = VerizonRouterClient.from_settings(settings)
    r = client.login(settings.username, settings.password.get_secret_value())
    r.raise_for_status()
    return client
