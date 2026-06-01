"""Suppress known false positives when scanning CDN / edge hosts (Cloudflare Workers, Pages, etc.)."""
from __future__ import annotations

import re
from urllib.parse import urlparse

# Host suffixes where open 80/443/8443 and TLS cipher findings are expected edge noise.
CDN_EDGE_SUFFIXES = (
    ".workers.dev",
    ".pages.dev",
    ".cloudflare.net",
    ".trycloudflare.com",
)

# Standard reverse-proxy ports — not meaningful "open services" on CDN edge.
CDN_EDGE_PORTS = frozenset({80, 443, 8080, 8443})

# Nuclei SSL/TLS templates that commonly fire on Cloudflare with no actionable fix.
NUCLEI_NOISE_TITLE_PATTERNS = (
    re.compile(r"weak\s+cipher", re.I),
    re.compile(r"cipher\s+suite", re.I),
    re.compile(r"ssl.*weak", re.I),
    re.compile(r"tls.*1\.0", re.I),
    re.compile(r"deprecated.*tls", re.I),
    re.compile(r"insecure.*ssl", re.I),
)


def _host_from_target(target: str, default: str) -> str:
    t = (target or default).strip()
    if "://" in t:
        try:
            return urlparse(t).hostname or default
        except Exception:
            return default
    return t.split(":")[0].lower()


def is_cdn_edge_host(fqdn: str) -> bool:
    host = fqdn.lower().strip().rstrip(".")
    return any(host.endswith(suffix) or host == suffix.lstrip(".") for suffix in CDN_EDGE_SUFFIXES)


def filter_finding_noise(fqdn: str, findings: list[dict], *, enabled: bool = True) -> list[dict]:
    if not enabled or not findings or not is_cdn_edge_host(fqdn):
        return findings

    out: list[dict] = []
    seen_vuln: set[tuple[str, str]] = set()
    dropped = 0

    for f in findings:
        ftype = f.get("finding_type", "")
        title = (f.get("title") or "").strip()
        title_key = title.lower()

        if ftype == "open_port" and f.get("port") in CDN_EDGE_PORTS:
            dropped += 1
            continue

        if ftype == "vuln" and any(p.search(title) for p in NUCLEI_NOISE_TITLE_PATTERNS):
            dropped += 1
            continue

        if ftype == "vuln":
            target_host = _host_from_target(f.get("target", ""), fqdn)
            dedupe_key = (title_key, target_host)
            if dedupe_key in seen_vuln:
                dropped += 1
                continue
            seen_vuln.add(dedupe_key)

        out.append(f)

    if dropped:
        from celery.utils.log import get_task_logger

        get_task_logger(__name__).info(
            f"[scan_noise] suppressed {dropped} CDN edge finding(s) for {fqdn}"
        )

    return out
