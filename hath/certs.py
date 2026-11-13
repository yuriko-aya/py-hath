"""PKCS#12 download and PEM conversion."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

logger = logging.getLogger(__name__)


def get_ssl_certificate(force_refresh: bool = False) -> bool:
    """Get SSL certificate from remote server.

    The certificate will be downloaded if:
    - No certificate exists
    - Existing certificate expires within 3 days
    - Existing certificate is more than one week old
    - force_refresh is True
    """
    from hath.config import current_config, rpc_path
    from hath.rpc import _make_rpc_request

    cfg = current_config()
    if not force_refresh and _check_certificate_validity():
        logger.debug("Using existing valid certificate")
        return True

    if force_refresh:
        logger.debug("Force refresh requested, downloading new certificate...")

    try:
        url_path = rpc_path("get_cert")

        logger.debug("Downloading new SSL certificate...")
        response = _make_rpc_request(url_path, timeout=30)

        p12_path = os.path.join(cfg.data_dir, "client.p12")
        with open(p12_path, "wb") as f:
            f.write(response.content)

        _convert_p12_to_pem(p12_path)

        logger.debug("SSL certificate downloaded and converted successfully")
        return True

    except Exception as e:
        logger.error(f"Error getting SSL certificate: {e}")
        return False


def _convert_p12_to_pem(p12_path: str) -> None:
    """Convert PKCS#12 certificate to separate PEM files with full certificate chain."""
    from hath.config import current_config

    cfg = current_config()
    try:
        with open(p12_path, "rb") as f:
            p12_data = f.read()

        if not cfg.client_key:
            raise ValueError("Client key is required for PKCS#12 conversion")

        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, cfg.client_key.encode()
        )

        if not certificate:
            raise ValueError("No certificate found in PKCS#12 file")

        if not private_key:
            raise ValueError("No private key found in PKCS#12 file")

        cert_path = os.path.join(cfg.data_dir, "client.crt")
        with open(cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

            if additional_certificates:
                logger.debug(f"Adding {len(additional_certificates)} intermediate certificates to chain")
                for intermediate_cert in additional_certificates:
                    f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
            else:
                logger.warning("No intermediate certificates found in PKCS#12 file")

        cfg.cert_file = cert_path

        key_path = os.path.join(cfg.data_dir, "client.key")
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        cfg.key_file = key_path

        logger.debug(f"Certificate saved to: {cert_path}")
        logger.debug(f"Private key saved to: {key_path}")

    except Exception as e:
        logger.error(f"Error converting PKCS#12 certificate: {e}")
        raise


def _check_certificate_validity() -> bool:
    """Check if existing certificate is valid, not older than a week, and expires in more than 3 days."""
    from hath.config import current_config

    cfg = current_config()
    try:
        cert_path = os.path.join(cfg.data_dir, "client.crt")
        key_path = os.path.join(cfg.data_dir, "client.key")

        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            logger.debug("Certificate files not found")
            return False

        cert_stat = os.stat(cert_path)
        cert_mtime = datetime.fromtimestamp(cert_stat.st_mtime)
        current_time = datetime.now()
        age_delta = current_time - cert_mtime

        logger.debug(f"Certificate file last modified: {cert_mtime}")
        logger.debug(f"Certificate age: {age_delta.days} days, {age_delta.seconds // 3600} hours")

        if age_delta.days >= 7:
            logger.debug("Certificate is more than one week old, will download new one")
            return False

        with open(cert_path, "rb") as f:
            cert_data = f.read()

        certificate = x509.load_pem_x509_certificate(cert_data)

        expiration_date = certificate.not_valid_after_utc
        current_date = datetime.now(timezone.utc)
        days_until_expiration = (expiration_date - current_date).days

        logger.debug(f"Certificate expires on: {expiration_date}")
        logger.debug(f"Days until expiration: {days_until_expiration}")

        if days_until_expiration > 3:
            logger.debug("Certificate is valid, not too old, and has more than 3 days until expiration")
            cfg.cert_file = cert_path
            cfg.key_file = key_path
            return True
        logger.debug("Certificate expires within 3 days, will download new one")
        return False

    except Exception as e:
        logger.error(f"Error checking certificate validity: {e}")
        return False
