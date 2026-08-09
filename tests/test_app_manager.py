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
