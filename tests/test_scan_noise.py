from app.tasks.scan_noise import filter_finding_noise, is_cdn_edge_host


def test_cdn_host_detection():
    assert is_cdn_edge_host("asm-dashboard.acesentineladmin.workers.dev")
    assert not is_cdn_edge_host("example.com")


def test_filters_edge_ports_and_weak_cipher():
    fqdn = "app.example.workers.dev"
    findings = [
        {"finding_type": "open_port", "port": 443, "title": "Open port 443"},
        {"finding_type": "open_port", "port": 22, "title": "Open port 22"},
        {"finding_type": "vuln", "title": "Weak Cipher Suites Detection", "target": f"https://{fqdn}"},
        {"finding_type": "vuln", "title": "Weak Cipher Suites Detection", "target": f"https://{fqdn}"},
        {"finding_type": "vuln", "title": "SQL Injection", "target": f"https://{fqdn}/login"},
    ]
    out = filter_finding_noise(fqdn, findings)
    assert len(out) == 2
    assert out[0]["port"] == 22
    assert out[1]["title"] == "SQL Injection"
