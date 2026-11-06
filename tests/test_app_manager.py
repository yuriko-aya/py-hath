from unittest.mock import patch

from app_manager import app, parse_additional_params


def test_parse_additional_params():
    assert parse_additional_params('') == {}
    assert parse_additional_params('a=1;b=2') == {'a': '1', 'b': '2'}
    assert parse_additional_params('key=value with spaces') == {'key': 'value with spaces'}


def test_index_route():
    client = app.test_client()
    response = client.get('/')
    assert response.status_code == 200
    assert b'Hentai@Home Python Client' in response.data


def test_health_has_no_metrics_blob():
    client = app.test_client()
    response = client.get('/health')
    assert response.status_code in (200, 503)
    payload = response.get_json()
    assert 'checks' in payload
    assert 'metrics' not in payload


def test_status_proxies_aggregator():
    client = app.test_client()
    snapshot = {
        'status': 'ok',
        'metrics': {'cache_hits': 3},
        'download': {'active': False, 'last_error': '', 'galleries_completed': 0},
        'cache': {},
    }
    with patch('app_manager._status_actkey_ok', return_value=True), patch(
        'app_manager.get_status', return_value=snapshot
    ):
        response = client.get('/status/dummy')
    assert response.status_code == 200
    assert response.get_json()['metrics']['cache_hits'] == 3


def test_metrics_proxy_forbidden_without_key():
    client = app.test_client()
    response = client.get('/metrics/wrong')
    assert response.status_code in (403, 500)


def test_dashboard_and_history_proxy():
    client = app.test_client()
    with patch('app_manager._status_actkey_ok', return_value=True), patch(
        'app_manager.get_dashboard', return_value=b'<html><svg></svg></html>'
    ), patch('app_manager.get_history', return_value={'samples': [{'ts': 1}]}):
        dash = client.get('/dashboard/dummy')
        hist = client.get('/history/dummy')
    assert dash.status_code == 200
    assert b'<svg' in dash.data
    assert hist.status_code == 200
    assert hist.get_json()['samples'][0]['ts'] == 1
