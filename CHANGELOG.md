# Changelog

## 0.4.0

### Fixed
- First-run credential prompt now sets `Config.client_id` / `Config.client_key` immediately
- `disable_ip_check` default corrected in `run_gunicorn.py`
- Custom `data_dir`, `cache_dir`, and `download_dir` respected across modules

### Added
- `hath/` package with shared constants, paths, HTTP client, validation, and metrics
- `/health` readiness endpoint with certificate, disk, and DB checks
- Metrics and download status on `/status`
- Pytest suite and GitHub Actions CI (ruff + tests)
- `pyproject.toml`, `requirements-dev.txt`, deployment examples under `deploy/`
- Config hot-reload for log level on `refresh_settings`
- `trust_x_forwarded_for` and JSON logging options in `settings.py`
- SQLite `schema_version` table for future migrations

### Changed
- File serving uses `send_file()` for cache hits and streaming cache-on-miss
- Gunicorn launched via `gunicorn.conf.py` with sync workers by default (`worker_class = "sync"`)
- Removed unused `watchdog` and `waitress` dependencies
- Worker config cache path documented as `config/config.json`
