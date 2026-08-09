# Improvement TODO

Most items from the initial review have been implemented in v0.4.0. See [CHANGELOG.md](CHANGELOG.md).

## Remaining / future work

- [ ] **Full package layout** — Move manager modules into `hath/` (currently only shared utilities live there)
- [ ] **Explicit Config singleton instance** — Replace class-level state bag with a testable dataclass singleton
- [ ] **Broader integration tests** — Mock RPC for `/h/` cache miss and `/servercmd/` flows
- [ ] **Prometheus metrics export** — Optional `/metrics` in Prometheus text format
- [ ] **Additional config hot-reload** — Apply throttle and other safe server settings without restart
- [ ] **Database migration runner** — Extend `schema_version` when schema changes beyond v1

## Completed (0.4.0)

- [x] First-run credential bug, `disable_ip_check` default, path hardcoding
- [x] Stream file responses (`send_file` + streaming cache-on-miss)
- [x] Pytest suite, `.gitignore` fix, GitHub Actions CI
- [x] Gunicorn/gevent configuration via `gunicorn.conf.py` + `worker_class` setting
- [x] `pyproject.toml`, dev dependencies, deployment examples
- [x] Centralized version/HTTP client, validation, metrics, `/health`
- [x] Remove unused deps, README sync, ARCHITECTURE/CONTRIBUTING/CHANGELOG docs
