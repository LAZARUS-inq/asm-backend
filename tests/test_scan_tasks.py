"""Unit tests for nuclei URL selection and JSONL parsing."""
from app.tasks.scan_tasks import (
    _nuclei_target_urls,
    _parse_nuclei_jsonl,
)


def test_nuclei_urls_http_only_when_port_80():
    ports = [{"port": 80, "finding_type": "open_port"}]
    assert _nuclei_target_urls("testphp.vulnweb.com", ports) == ["http://testphp.vulnweb.com"]


def test_nuclei_urls_http_fallback_when_no_ports(monkeypatch):
    monkeypatch.setattr("app.tasks.scan_tasks._probe_tcp_ports", lambda fqdn: set())
    urls = _nuclei_target_urls("example.com", None)
    assert urls == ["http://example.com"]


def test_nuclei_urls_https_when_443_open():
    ports = [{"port": 443, "finding_type": "open_port"}]
    assert _nuclei_target_urls("example.com", ports) == ["https://example.com"]


def test_parse_nuclei_jsonl_finding():
    line = (
        '{"template-id":"test","info":{"name":"SQL Injection","severity":"high",'
        '"description":"test desc","classification":{"cve-id":["CVE-2024-0001"]}},'
        '"matched-at":"http://testphp.vulnweb.com/artists.php"}'
    )
    findings = _parse_nuclei_jsonl(line + "\n", "testphp.vulnweb.com")
    assert len(findings) == 1
    assert findings[0]["title"] == "SQL Injection"
    assert findings[0]["severity"] == "high"
    assert findings[0]["cve_id"] == "CVE-2024-0001"
    assert "artists.php" in findings[0]["target"]


def test_parse_nuclei_jsonl_skips_banner_lines():
    stdout = "some log line\nnot json\n"
    assert _parse_nuclei_jsonl(stdout, "x.com") == []


def test_unreachable_target_returns_scan_error(monkeypatch):
    monkeypatch.setattr(
        "app.tasks.scan_tasks._http_probe",
        lambda url, timeout=10: (False, "connection refused"),
    )
    monkeypatch.setattr(
        "app.tasks.scan_tasks._nuclei_template_args",
        lambda: ["-t", "/nuclei-templates/http/vulnerabilities", "-tags", "sqli"],
    )
    from app.tasks.scan_tasks import _run_vuln_scan

    findings = _run_vuln_scan("testphp.vulnweb.com", [])
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "scan_error"
    assert "unreachable" in findings[0]["title"].lower()


def test_http_probe_success(monkeypatch):
    class FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("app.tasks.scan_tasks.urlopen", lambda req, timeout: FakeResp())
    from app.tasks.scan_tasks import _http_probe

    ok, detail = _http_probe("http://example.com")
    assert ok is True
    assert "200" in detail


def test_nuclei_template_args_tags_mode(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "nuclei_scan_mode", "tags")
    monkeypatch.setattr(settings, "nuclei_scan_tags", "sqli,xss")
    monkeypatch.setattr(
        "app.tasks.scan_tasks._nuclei_templates_root",
        lambda: "/nuclei-templates",
    )
    valid = {
        "/nuclei-templates",
        "/nuclei-templates/http/vulnerabilities/generic",
        "/nuclei-templates/http/exposures",
        "/nuclei-templates/http/misconfiguration",
    }
    monkeypatch.setattr(
        "app.tasks.scan_tasks.os.path.isdir",
        lambda path: path in valid,
    )
    from app.tasks.scan_tasks import _nuclei_template_args

    assert _nuclei_template_args() == [
        "-t", "/nuclei-templates/http/vulnerabilities/generic",
        "-t", "/nuclei-templates/http/exposures",
        "-t", "/nuclei-templates/http/misconfiguration",
        "-tags", "sqli,xss",
    ]


def test_pick_primary_scan_url_prefers_https():
    from app.tasks.scan_tasks import _pick_primary_scan_url

    urls = _pick_primary_scan_url([
        "http://example.com",
        "https://example.com",
    ])
    assert urls == ["https://example.com"]


def test_expand_firing_range_urls():
    from app.tasks.scan_tasks import _expand_scan_urls

    urls = _expand_scan_urls(
        ["https://public-firing-range.appspot.com"],
        "public-firing-range.appspot.com",
    )
    assert len(urls) >= 5
    assert any("reflected" in u for u in urls)
