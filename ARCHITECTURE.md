# Architecture

## Startup sequence

```mermaid
sequenceDiagram
    participant RG as run_gunicorn.py
    participant CM as config_manager
    participant RPC as rpc_manager
    participant DB as db_manager
    participant BM as background_manager
    participant GN as Gunicorn

    RG->>CM: initialize(settings)
    CM->>RPC: server_stat, client_login, get_cert
    RG->>DB: initialize_database()
    RG->>DB: cache_validation()
    RG->>BM: start_background_task()
    RG->>GN: gunicorn -c gunicorn.conf.py wsgi:application
    BM->>RPC: client_start (after port ready)
    BM->>BM: periodic still_alive (every 2 min)
```

## Cache miss (`GET /h/...`)

```mermaid
sequenceDiagram
    participant Client
    participant App as app_manager
    participant VM as verification_manager
    participant Cache as cache_manager
    participant RPC as rpc_manager
    participant DB as db_manager

    Client->>App: GET /h/{file_id}/...
    App->>VM: verify keystamp
    alt file on disk and valid
        App->>DB: update_last_access
        App-->>Client: send_file (stream)
    else miss or corrupt
        App->>Cache: fetch_remote_file
        Cache->>RPC: srfetch
        Cache->>Cache: download from mirror URL
        App-->>Client: generate_and_cache (stream + write)
    end
```

## Server command dispatch

```mermaid
sequenceDiagram
    participant RPC as H@H RPC server
    participant App as app_manager
    participant VM as verification_manager

    RPC->>App: /servercmd/{cmd}/...
    App->>App: IP check (rpc_server_ips)
    App->>VM: verify_servercmd_key
    alt still_alive / speed_test / refresh_*
        App-->>RPC: command response
    else start_downloader
        App->>App: download_manager.trigger_download()
    end
```

## Shutdown

1. `SIGINT` / `SIGTERM` → `background_manager.notify_client_stop()`
2. RPC `client_stop` sent if startup completed
3. `config/config.json` removed; DB connections closed
4. Gunicorn workers exit

## Configuration flow

- **Main process**: `config_manager.initialize()` fetches live config from RPC and writes `config/config.json`
- **Gunicorn workers**: `create_app()` loads cached JSON via `load_from_config_file()`
- **Paths**: `settings.py` → `initialize()` → `Config.*` → `hath.paths` helpers

## Gunicorn reload (cert refresh)

`refresh_cert` servercmd downloads a new PKCS#12 bundle, then sends `SIGUSR2` to the Gunicorn master (see `event_manager.restart_gunicorn()`). Workers reload with the updated certificate files on disk.
