# Improvement TODO

Most items from the initial review have been implemented in v0.4.0. See [CHANGELOG.md](CHANGELOG.md).

## Completed (0.4.0)

- [x] First-run credential bug, `disable_ip_check` default, path hardcoding
- [x] Stream file responses (`send_file` + streaming cache-on-miss)
- [x] Pytest suite, `.gitignore` fix, GitHub Actions CI
- [x] Gunicorn/gevent configuration via `gunicorn.conf.py` + `worker_class` setting
- [x] `pyproject.toml`, dev dependencies, deployment examples
- [x] Centralized version/HTTP client, validation, metrics, `/health`
- [x] Remove unused deps, README sync, ARCHITECTURE/CONTRIBUTING/CHANGELOG docs
- [x] **Full package layout** — Manager modules live in `hath/`
- [x] **Explicit Config singleton instance** — Dataclass singleton via `get_config()` / `replace_config()`
- [x] **Broader integration tests** — Mocked `/h/` cache hit and miss, and `/servercmd/` flows
- [x] **Prometheus metrics export** — `GET /metrics/<actkey>` proxies Prometheus text from the stats socket
- [x] **Additional config hot-reload** — Throttle, disk limits, and log level follow a newer `config.json` without restart
