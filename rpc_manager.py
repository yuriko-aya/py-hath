import logging
import time

import config_manager
from hath.http_client import get
from hath.metrics import record_rpc_request

logger = logging.getLogger(__name__)


def _make_rpc_request(url_path: str, timeout: int = 10):
    """Make RPC request with failover logic."""
    hath_config = config_manager.Config()

    if not hath_config:
        raise RuntimeError("HathConfig is not initialized")

    proxies = {}
    if hath_config.rpc_proxy:
        proxies.update({
            'http': hath_config.rpc_proxy,
            'https': hath_config.rpc_proxy,
        })

    if 'act=server_stat' in url_path or 'act=client_login' in url_path:
        url = f"http://{hath_config.rpc_fallback_domain}{url_path}"
        logger.debug(f"Making RPC request to fallback domain: {url} via proxy: {hath_config.rpc_proxy}")
        return _request_with_metrics(url, timeout, proxies)

    if not hath_config.rpc_server_ips:
        url = f"http://{hath_config.rpc_fallback_domain}{url_path}"
        logger.debug(f"No RPC IP list available, using fallback domain: {url} via proxy: {hath_config.rpc_proxy}")
        return _request_with_metrics(url, timeout, proxies)

    ip_attempts = 0
    max_ip_attempts = len(hath_config.rpc_server_ips)

    while ip_attempts < max_ip_attempts:
        current_host = config_manager._get_rpc_host()
        url = f"http://{current_host}{url_path}"

        retry_attempts = 0
        max_retries = 3

        while retry_attempts < max_retries:
            try:
                if retry_attempts == 0:
                    logger.debug(f"Making RPC request to: {url} via proxy: {hath_config.rpc_proxy}")
                else:
                    logger.debug(f"Retrying RPC request to {current_host} (attempt {retry_attempts + 1}/{max_retries})")

                return _request_with_metrics(url, timeout, proxies)

            except Exception as e:
                retry_attempts += 1
                if retry_attempts < max_retries:
                    logger.warning(f"RPC request failed to {current_host} (attempt {retry_attempts}/{max_retries}): {e}")
                    time.sleep(1)
                else:
                    logger.warning(f"RPC request failed to {current_host} after {max_retries} attempts: {e}")

        config_manager._handle_rpc_failure()
        ip_attempts += 1

        if ip_attempts < max_ip_attempts:
            logger.debug(f"Moving to next RPC server: {config_manager._get_rpc_host()}")

    logger.error("All RPC server IPs failed, trying fallback domain as last resort")
    url = f"http://{hath_config.rpc_fallback_domain}{url_path}"
    return _request_with_metrics(url, timeout, proxies)


def _request_with_metrics(url: str, timeout: int, proxies: dict):
    start = time.perf_counter()
    try:
        response = get(url, timeout=timeout, proxies=proxies or None)
        response.raise_for_status()
        record_rpc_request((time.perf_counter() - start) * 1000)
        return response
    except Exception:
        record_rpc_request((time.perf_counter() - start) * 1000, error=True)
        raise
