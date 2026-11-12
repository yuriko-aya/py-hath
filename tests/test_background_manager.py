import config_manager
from background_manager import resolve_listen_port


def test_resolve_listen_port_uses_server_port_by_default():
    config_manager.Config.override_port = False
    config_manager.Config.hath_port = 8443
    config_manager.Config.config = {'port': 443}
    assert resolve_listen_port(config_manager.Config) == 443


def test_resolve_listen_port_uses_override_when_enabled():
    config_manager.Config.override_port = True
    config_manager.Config.hath_port = 8443
    config_manager.Config.config = {'port': 443}
    assert resolve_listen_port(config_manager.Config) == 8443
