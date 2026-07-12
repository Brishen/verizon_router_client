import pytest

from verizon_router_client.config import RouterSettings

pytestmark = pytest.mark.usefixtures("isolated_env")


def test_defaults():
    settings = RouterSettings()
    assert settings.base_url == "https://192.168.1.1"
    assert settings.username == "admin"
    assert settings.password.get_secret_value() == ""
    assert settings.verify_tls is None
    assert settings.tls_hostname is None
    assert settings.timeout_s == 10.0


def test_reads_prefixed_env_vars(monkeypatch):
    monkeypatch.setenv("VZ_ROUTER_BASE_URL", "https://10.0.0.1")
    monkeypatch.setenv("VZ_ROUTER_PASSWORD", "sekrit")
    settings = RouterSettings()
    assert settings.base_url == "https://10.0.0.1"
    assert settings.password.get_secret_value() == "sekrit"


def test_reads_dotenv_from_cwd(isolated_env):
    (isolated_env / ".env").write_text(
        "VZ_ROUTER_BASE_URL=https://10.1.1.1\nVZ_ROUTER_PASSWORD=from-dotenv\n"
    )
    settings = RouterSettings()
    assert settings.base_url == "https://10.1.1.1"
    assert settings.password.get_secret_value() == "from-dotenv"


def test_env_var_beats_dotenv(isolated_env, monkeypatch):
    (isolated_env / ".env").write_text("VZ_ROUTER_PASSWORD=from-dotenv\n")
    monkeypatch.setenv("VZ_ROUTER_PASSWORD", "from-env")
    assert RouterSettings().password.get_secret_value() == "from-env"


def test_password_repr_is_masked():
    settings = RouterSettings(password="sekrit")
    assert "sekrit" not in repr(settings)
    assert "sekrit" not in str(settings)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("true", True),
        ("True", True),
        ("1", True),
        ("yes", True),
        ("false", False),
        ("False", False),
        ("0", False),
        ("no", False),
        ("off", False),
    ],
)
def test_verify_tls_bool_coercion(monkeypatch, raw, expected):
    monkeypatch.setenv("VZ_ROUTER_VERIFY_TLS", raw)
    assert RouterSettings().verify_tls is expected


def test_verify_tls_ca_path_preserved(monkeypatch):
    monkeypatch.setenv("VZ_ROUTER_VERIFY_TLS", "/path/to/ca.pem")
    assert RouterSettings().verify_tls == "/path/to/ca.pem"
