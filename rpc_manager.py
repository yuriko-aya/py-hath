import requests
import logging
import time

logger = logging.getLogger(__name__)

requests_headers = {
    'User-Agent': 'Hentai@Home Python Client 0.2'
}

def _make_rpc_request(url_path: str, timeout: int = 10, configuration = None) -> requests.Response:
    """Make RPC request with failover logic.

    Args:
        url_path: The URL path including query parameters (e.g., "/15/rpc?act=server_stat")
        timeout: Request timeout in seconds
        
    Returns:
        requests.Response object
        
    Raises:
        requests.RequestException: If all servers fail
    """
    if configuration is not None:
        hath_config = configuration
    else:
        from config_singleton import get_hath_config
        hath_config = get_hath_config()

    if not hath_config:
        raise RuntimeError("HathConfig is not initialized") 

    # For server_stat and server_login, always use the fallback domain
    if 'act=server_stat' in url_path or 'act=client_login' in url_path:
        url = f"http://{hath_config.rpc_fallback_domain}{url_path}"
        logger.debug(f"Making RPC request to fallback domain: {url}")
        response = requests.get(url, headers=requests_headers, timeout=timeout)
        response.raise_for_status()
        return response

    # For other requests, use the dynamic IP list with failover
    if not hath_config.rpc_server_ips:
        # No IP list available, use fallback domain
        url = f"http://{hath_config.rpc_fallback_domain}{url_path}"
        logger.debug(f"No RPC IP list available, using fallback domain: {url}")
        response = requests.get(url, headers=requests_headers, timeout=timeout)
        response.raise_for_status()
        return response

    # Try each IP in the list
    original_list = hath_config.rpc_server_ips.copy()
    ip_attempts = 0
    max_ip_attempts = len(hath_config.rpc_server_ips)

    while ip_attempts < max_ip_attempts:
        current_host = hath_config._get_rpc_host()
        url = f"http://{current_host}{url_path}"
        
        # Try the current IP up to 3 times
        retry_attempts = 0
        max_retries = 3
        
        while retry_attempts < max_retries:
            try:
                if retry_attempts == 0:
                    logger.debug(f"Making RPC request to: {url}")
                else:
                    logger.debug(f"Retrying RPC request to {current_host} (attempt {retry_attempts + 1}/{max_retries})")

                response = requests.get(url, headers=requests_headers, timeout=timeout)
                response.raise_for_status()
                return response
                
            except Exception as e:
                retry_attempts += 1
                if retry_attempts < max_retries:
                    logger.warning(f"RPC request failed to {current_host} (attempt {retry_attempts}/{max_retries}): {e}")
                    time.sleep(1)  # Brief delay between retries
                else:
                    logger.warning(f"RPC request failed to {current_host} after {max_retries} attempts: {e}")
        
        # All retries for this IP failed, move to next IP
        hath_config._handle_rpc_failure()
        ip_attempts += 1
        
        if ip_attempts < max_ip_attempts:
            logger.debug(f"Moving to next RPC server: {hath_config._get_rpc_host()}")

    # All IPs failed, try fallback domain as last resort
    logger.error("All RPC server IPs failed, trying fallback domain as last resort")
    url = f"http://{hath_config.rpc_fallback_domain}{url_path}"
    response = requests.get(url, headers=requests_headers, timeout=timeout)
    response.raise_for_status()
    return response