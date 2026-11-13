"""Shared query-string helpers for H@H HTTP routes."""


def parse_additional_params(additional: str) -> dict:
    """Parse additional parameters from key=value;key=value format."""
    params = {}
    if additional:
        for pair in additional.split(';'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key.strip()] = value.strip()
    return params
