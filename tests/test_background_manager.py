from hath.config import Config, replace_config
from hath.lifecycle import resolve_listen_port


def test_resolve_listen_port_uses_server_port():
    cfg = replace_config(Config(override_port=False, hath_port=8443, server={'port': 443}))
    assert resolve_listen_port(cfg) == 443


def test_resolve_listen_port_uses_override():
    cfg = replace_config(Config(override_port=True, hath_port=8443, server={'port': 443}))
    assert resolve_listen_port(cfg) == 8443
