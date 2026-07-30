# Contributing

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .
```

## Tests

```bash
pytest -q
ruff check .
```

## Simulating servercmd locally

Generate a valid key (replace values with your client ID/key):

```python
import hashlib, time
client_id = "YOUR_ID"
client_key = "YOUR_KEY"
command = "still_alive"
additional = ""
time_param = str(int(time.time()))
data = f"hentai@home-servercmd-{command}-{additional}-{client_id}-{time_param}-{client_key}"
key = hashlib.sha1(data.encode()).hexdigest()
print(f"https://localhost:PORT/servercmd/{command}/{time_param}/{key}")
```

For NAT or reverse-proxy setups, set `disable_ip_check = True` or configure `trust_x_forwarded_for` only behind a trusted proxy.

## Code style

- Match existing module layout and naming
- Use `hath.paths` for filesystem paths (never hardcode `data/` or `cache/`)
- Use `hath.http_client` for outbound HTTP
- Run `ruff check .` before opening a PR
