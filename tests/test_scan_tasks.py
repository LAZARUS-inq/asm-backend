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


def test_nuclei_template_args_tags_mode(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "nuclei_scan_mode", "tags")
    monkeypatch.setattr(settings, "nuclei_scan_tags", "sqli,xss")
    monkeypatch.setattr(
        "app.tasks.scan_tasks._nuclei_templates_root",
        lambda: "/nuclei-templates",
    )
    monkeypatch.setattr(
        "app.tasks.scan_tasks.NUCLEI_TAGS_ROOT",
        "/nuclei-templates/http/vulnerabilities",
    )
    monkeypatch.setattr(
        "app.tasks.scan_tasks.os.path.isdir",
        lambda path: path in (
            "/nuclei-templates",
            "/nuclei-templates/http/vulnerabilities",
        ),
    )
    from app.tasks.scan_tasks import _nuclei_template_args

    assert _nuclei_template_args() == [
        "-t",
        "/nuclei-templates/http/vulnerabilities",
        "-tags",
        "sqli,xss",
    ]
