from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse

import pytest
import requests

from verizon_router_client.cr1000a import VerizonRouterClient

PROJECT_ENV = Path(__file__).resolve().parent.parent / ".env"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--router",
        choices=("auto", "mock", "real"),
        default="auto",
        help=(
            "Backend for integration tests: the in-process mock service, the "
            "real router (credentials from the project .env), or auto "
            "(real when .env has a password, mock otherwise)."
        ),
    )


def _real_settings():
    """RouterSettings from the project .env, or None if unusable."""
    from verizon_router_client.config import RouterSettings

    if not PROJECT_ENV.is_file():
        return None
    settings = RouterSettings(_env_file=PROJECT_ENV)
    if not settings.password.get_secret_value():
        return None
    return settings


class FakeResponse:
    def __init__(
        self,
        text: str = "",
        json_data: Any = None,
        status_code: int = 200,
    ) -> None:
        self.text = text
        self._json_data = json_data
        self.status_code = status_code

    def json(self) -> Any:
        if self._json_data is None:
            raise ValueError("No JSON")
        return self._json_data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")


class FakeSession:
    """Stands in for requests.Session; routes by URL path."""

    def __init__(self, routes: dict[str, FakeResponse]) -> None:
        self.routes = routes
        self.calls: list[dict[str, Any]] = []

    def mount(self, prefix: str, adapter: Any) -> None:
        pass

    def _handle(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        path = urlparse(url).path
        self.calls.append({"method": method, "path": path, **kwargs})
        if path not in self.routes:
            raise AssertionError(f"Unexpected request: {method} {path}")
        return self.routes[path]

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        return self._handle("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        return self._handle("POST", url, **kwargs)


@pytest.fixture
def make_client():
    def _make(
        routes: dict[str, FakeResponse],
    ) -> tuple[VerizonRouterClient, FakeSession]:
        session = FakeSession(routes)
        client = VerizonRouterClient(session=session, verify_tls=False)
        return client, session

    return _make


@pytest.fixture
def mock_router():
    from tests.mock_router import MockRouter

    router = MockRouter()
    router.start()
    yield router
    router.stop()


@pytest.fixture(scope="session")
def router_mode(request: pytest.FixtureRequest) -> str:
    mode = request.config.getoption("--router")
    if mode == "auto":
        mode = "real" if _real_settings() is not None else "mock"
    if mode == "real" and _real_settings() is None:
        pytest.skip("--router=real needs a project .env with VZ_ROUTER_PASSWORD")
    return mode


@pytest.fixture(scope="session")
def _real_shared_client(router_mode: str):
    """One logged-in client for the whole session.

    The real router throttles rapid logins (403s after a burst), so tests
    must share a single authenticated session instead of logging in each.
    """
    if router_mode != "real":
        return None
    settings = _real_settings()
    client = VerizonRouterClient.from_settings(settings)
    r = client.login(settings.username, settings.password.get_secret_value())
    if r.status_code != 200:
        pytest.skip(
            f"Real router rejected login (HTTP {r.status_code}); "
            "it may be throttling after recent login attempts."
        )
    return client


@pytest.fixture
def router_target(router_mode: str, _real_shared_client):
    """The selected integration backend: mock service or the real router."""
    if router_mode == "mock":
        from tests.mock_router import MockRouter

        router = MockRouter()
        router.start()
        yield SimpleNamespace(
            is_mock=True,
            mock=router,
            settings=None,
            username=router.state.username,
            password=router.state.password,
            logged_in_client=None,
            make_client=lambda: VerizonRouterClient(
                base_url=router.base_url, verify_tls=False
            ),
        )
        router.stop()
    else:
        settings = _real_settings()
        yield SimpleNamespace(
            is_mock=False,
            mock=None,
            settings=settings,
            username=settings.username,
            password=settings.password.get_secret_value(),
            logged_in_client=_real_shared_client,
            make_client=lambda: VerizonRouterClient.from_settings(settings),
        )


@pytest.fixture
def isolated_env(monkeypatch, tmp_path):
    """No VZ_ROUTER_* env vars and a cwd without the project's real .env."""
    for key in list(os.environ):
        if key.startswith("VZ_ROUTER_"):
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)
    return tmp_path
