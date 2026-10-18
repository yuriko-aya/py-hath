"""Server-rendered SVG dashboard for 24h in-memory samples."""

from __future__ import annotations

from html import escape
from typing import Any, Iterable


def _svg_polyline(values: list[float], *, width: int = 720, height: int = 140, color: str = "#4fc3f7") -> str:
    if not values:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'width="100%" height="{height}">'
            f'<text x="12" y="{height // 2}" fill="#888" font-size="14">No samples yet</text></svg>'
        )
    vmin = min(values)
    vmax = max(values)
    if vmax <= vmin:
        vmax = vmin + 1.0
    n = len(values)
    pts: list[str] = []
    for i, value in enumerate(values):
        x = 4 + (i / max(n - 1, 1)) * (width - 8)
        y = height - 4 - ((value - vmin) / (vmax - vmin)) * (height - 8)
        pts.append(f"{x:.1f},{y:.1f}")
    label = f"{vmin:g} – {vmax:g}"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}">'
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#111" rx="6"/>'
        f'<polyline fill="none" stroke="{color}" stroke-width="1.5" points="{" ".join(pts)}"/>'
        f'<text x="8" y="16" fill="#aaa" font-size="11">{escape(label)}</text></svg>'
    )


def _series(samples: Iterable[dict[str, Any]], key: str) -> list[float]:
    out: list[float] = []
    for sample in samples:
        value = sample.get(key)
        if value is None:
            out.append(0.0)
        else:
            out.append(float(value))
    return out


def render_dashboard_html(samples: list[dict[str, Any]]) -> str:
    charts = (
        ("Cache hits / min", "hits_per_min", "#4fc3f7"),
        ("Bytes served / min", "bytes_per_min", "#81c784"),
        ("RPC requests / min", "rpc_per_min", "#ffb74d"),
        ("Hit rate (per minute)", "hit_rate", "#ce93d8"),
        ("Download active", "download_active", "#ef9a9a"),
    )
    sections = []
    for title, key, color in charts:
        values = _series(samples, key)
        sections.append(
            f"<section><h2>{escape(title)}</h2>{_svg_polyline(values, color=color)}</section>"
        )
    count = len(samples)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>H@H metrics (24h)</title>
<style>
body {{ margin: 0; font-family: system-ui, sans-serif; background: #0b0b0b; color: #eee; }}
main {{ max-width: 900px; margin: 0 auto; padding: 24px; }}
h1 {{ font-size: 1.25rem; font-weight: 600; }}
h2 {{ font-size: 0.9rem; font-weight: 500; color: #bbb; margin: 1.5rem 0 0.4rem; }}
p {{ color: #888; font-size: 0.85rem; }}
</style>
</head>
<body>
<main>
<h1>Hentai@Home — last 24 hours</h1>
<p>{count} one-minute samples (in-memory; resets on restart). Hit rate is hits/(hits+misses) for that minute.</p>
{"".join(sections)}
</main>
</body>
</html>
"""
