# Architecture

## Startup sequence

```mermaid
sequenceDiagram
    participant RG as run_gunicorn.py
    participant CM as hath.config
    participant RPC as hath.rpc
    participant DB as hath.db
    participant LC as hath.lifecycle
    participant GN as Gunicorn

    RG->>CM: initialize(settings)
    CM->>RPC: server_stat, client_login
    CM->>CM: hath.certs get_cert
    RG->>DB: initialize_database()
    RG->>DB: cache_validation()
    RG->>LC: start_background_task()
    RG->>RG: spawn stats aggregator (Unix socket)
    RG->>GN: gunicorn -c gunicorn.conf.py wsgi:application
    LC->>RPC: client_start (after port ready)
    LC->>LC: periodic still_alive (every 2 min)
```

## Cache miss (`GET /h/...`)

```mermaid
sequenceDiagram
    participant Client
    participant Files as hath.http.files
    participant VM as hath.verification
    participant Cache as hath.cache
    participant RPC as hath.rpc
    participant DB as hath.db

    Client->>Files: GET /h/{file_id}/...
    Files->>VM: verify keystamp
    alt file on disk and valid
        Files->>DB: update_last_access
        Files-->>Client: send_file (stream)
    else miss or corrupt
        Files->>Cache: fetch_remote_file
        Cache->>RPC: srfetch
        Cache->>Cache: download from mirror URL
        Files-->>Client: generate_and_cache (stream + write)
    end
```

## Server command dispatch

```mermaid
sequenceDiagram
    participant RPC as H@H RPC server
    participant Cmd as hath.http.servercmd
    participant VM as hath.verification

    RPC->>Cmd: /servercmd/{cmd}/...
    Cmd->>Cmd: IP check (rpc_server_ips)
    Cmd->>VM: verify_servercmd_key
    alt still_alive / speed_test / refresh_*
        Cmd-->>RPC: command response
    else start_downloader
        Cmd->>Cmd: hath.download.trigger_download()
    end
```

## Shutdown

1. `SIGINT` / `SIGTERM` → `hath.lifecycle.notify_client_stop()`
2. RPC `client_stop` sent if startup completed
3. `config/config.json` removed; DB connections closed
4. Gunicorn workers exit

## Configuration flow

- **Main process**: `hath.config.initialize()` fetches live config from RPC and writes `config/config.json`
- **Singleton**: one `Config` dataclass (`get_config()` / `replace_config()`). Server key/values live on `Config.server`
- **Gunicorn workers**: `hath.http.app.create_app()` loads cached JSON via `load_from_config_file()`
- **Hot reload**: a newer `config.json` reloads throttle, disk limits, RPC IPs, static ranges, and credentials into the existing process. Log level follows `disable_logging` or the local override. Listen port, data directories, and certificate paths stay as they were at process start. `refresh_settings` writes the file and does not restart Gunicorn
- **Paths**: `settings.py` → `initialize()` → `Config` → `hath.paths` helpers

## Metrics aggregation

Workers keep hot counters in memory and POST deltas every ~10s to `config/hath-stats.sock`. The parent process also pushes download gauges. Authenticated `GET /status/<actkey>` and `GET /metrics/<actkey>` on Gunicorn proxy that socket. `/metrics/<actkey>` is Prometheus text. `/health` is checks-only and is not a Prometheus target.

## Gunicorn reload (cert refresh)

`refresh_cert` servercmd downloads a new PKCS#12 bundle, then sends `SIGUSR2` to the Gunicorn master (see `hath.lifecycle.restart_gunicorn()`). Workers reload with the updated certificate files on disk. Host and port changes still require a process restart.
