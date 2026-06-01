"""
Scan tasks — real scanner implementations.
subfinder → subdomain enumeration
nmap      → port + service detection
nuclei    → vulnerability scanning
"""
from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import datetime, timezone

from celery import shared_task
from celery.utils.log import get_task_logger

from app.db.session import SessionLocal
from app.models.models import Domain, Finding, ScanJob, ScanStatus, Severity

logger = get_task_logger(__name__)

NUCLEI_TEMPLATES = "/nuclei-templates"

# Only scan these dirs — much faster than all templates
NUCLEI_SCAN_DIRS = [
    "/nuclei-templates/http/vulnerabilities",
    "/nuclei-templates/http/exposures",
    "/nuclei-templates/http/misconfiguration",
]


def utcnow():
    return datetime.now(timezone.utc)


SEVERITY_MAP = {
    "info":     Severity.info,
    "low":      Severity.low,
    "medium":   Severity.medium,
    "high":     Severity.high,
    "critical": Severity.critical,
}

RISK_SCORE_MAP = {
    Severity.info:     0.0,
    Severity.low:      2.5,
    Severity.medium:   5.0,
    Severity.high:     7.5,
    Severity.critical: 10.0,
}


def _save_findings(db, scan_job_id: str, results: list[dict]) -> None:
    for r in results:
        sev = SEVERITY_MAP.get(r.get("severity", "info"), Severity.info)
        finding = Finding(
            scan_job_id=uuid.UUID(scan_job_id),
            finding_type=r.get("finding_type", "unknown"),
            target=r.get("target", ""),
            port=r.get("port"),
            service=r.get("service", ""),
            severity=sev,
            title=r.get("title", ""),
            description=r.get("description", ""),
            cve_id=r.get("cve_id", ""),
            risk_score=RISK_SCORE_MAP.get(sev, 0.0),
            raw_output=r.get("raw_output", ""),
        )
        db.add(finding)
    db.commit()


def _run_subdomain_scan(fqdn: str) -> list[dict]:
    logger.info(f"[subfinder] scanning {fqdn}")
    try:
        result = subprocess.run(
            ["subfinder", "-d", fqdn, "-silent", "-json"],
            capture_output=True, text=True, timeout=120
        )
        findings = []
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            try:
                data = json.loads(line)
                subdomain = data.get("host", "")
            except json.JSONDecodeError:
                subdomain = line.strip()
            if subdomain and subdomain != fqdn:
                findings.append({
                    "finding_type": "subdomain",
                    "target": subdomain,
                    "severity": "info",
                    "title": f"Subdomain discovered: {subdomain}",
                    "description": "Active subdomain found via passive DNS enumeration.",
                    "raw_output": line,
                })
        logger.info(f"[subfinder] found {len(findings)} subdomains for {fqdn}")
        return findings
    except subprocess.TimeoutExpired:
        logger.warning(f"[subfinder] timeout for {fqdn}")
        return []
    except FileNotFoundError:
        logger.error("[subfinder] not installed or not in PATH")
        return []
    except Exception as e:
        logger.error(f"[subfinder] error: {e}")
        return []


def _run_port_scan(fqdn: str) -> list[dict]:
    logger.info(f"[nmap] scanning {fqdn}")
    try:
        result = subprocess.run(
            [
                "nmap", "-sV", "--open", "-T4",
                "-p", "21,22,23,25,53,80,443,445,3306,3389,5432,6379,8080,8443,8888,9200,27017",
                "-oX", "-", fqdn,
            ],
            capture_output=True, text=True, timeout=180
        )
        findings = []
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(result.stdout)
            for host in root.findall("host"):
                for port_el in host.findall(".//port"):
                    state = port_el.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    portid = int(port_el.get("portid", 0))
                    service_el = port_el.find("service")
                    service_name = service_str = ""
                    if service_el is not None:
                        service_name = service_el.get("name", "")
                        product = service_el.get("product", "")
                        version = service_el.get("version", "")
                        service_str = " ".join(filter(None, [product, version])) or service_name
                    severity = "info"
                    if portid in (23, 445):
                        severity = "high"
                    elif portid in (21, 3389):
                        severity = "medium"
                    elif portid in (6379, 27017, 9200):
                        severity = "high"
                    elif portid in (3306, 5432):
                        severity = "medium"
                    findings.append({
                        "finding_type": "open_port",
                        "target": fqdn,
                        "port": portid,
                        "service": service_str,
                        "severity": severity,
                        "title": f"Open port {portid}/{service_name} on {fqdn}",
                        "description": f"Port {portid} is open and running {service_str}.",
                        "raw_output": result.stdout[:500],
                    })
        except ET.ParseError as e:
            logger.warning(f"[nmap] XML parse error: {e}")
        logger.info(f"[nmap] found {len(findings)} open ports for {fqdn}")
        return findings
    except subprocess.TimeoutExpired:
        logger.warning(f"[nmap] timeout for {fqdn}")
        return []
    except FileNotFoundError:
        logger.error("[nmap] not installed or not in PATH")
        return []
    except Exception as e:
        logger.error(f"[nmap] error: {e}")
        return []


def _run_vuln_scan(fqdn: str) -> list[dict]:
    logger.info(f"[nuclei] scanning {fqdn}")

    # Use specific dirs if they exist, else fall back to full templates
    scan_dirs = [d for d in NUCLEI_SCAN_DIRS if os.path.isdir(d)]
    if not scan_dirs and os.path.isdir(NUCLEI_TEMPLATES):
        scan_dirs = [NUCLEI_TEMPLATES]

    if scan_dirs:
        logger.info(f"[nuclei] using {len(scan_dirs)} template dirs")
    else:
        logger.warning("[nuclei] no templates found, nuclei will try to download")

    cmd = ["nuclei", "-u", f"https://{fqdn}"]

    for d in scan_dirs:
        cmd += ["-t", d]

    cmd += [
        "-severity", "low,medium,high,critical",
        "-json-export", "-",
        "-silent",
        "-timeout", "10",
        "-rate-limit", "50",
        "-bulk-size", "25",
        "-concurrency", "25",
        "-duc",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        findings = []
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            try:
                data = json.loads(line)
                severity = data.get("info", {}).get("severity", "info").lower()
                name = data.get("info", {}).get("name", "Unknown")
                matched_at = data.get("matched-at", fqdn)
                description = data.get("info", {}).get("description", "")
                cve_id = ""
                for tag in data.get("info", {}).get("classification", {}).get("cve-id", []):
                    cve_id = tag
                    break
                findings.append({
                    "finding_type": "vuln",
                    "target": matched_at,
                    "severity": severity,
                    "title": name,
                    "description": description,
                    "cve_id": cve_id,
                    "raw_output": line[:1000],
                })
            except json.JSONDecodeError:
                continue
        logger.info(f"[nuclei] found {len(findings)} vulns for {fqdn}")
        if result.stderr:
            logger.info(f"[nuclei] stderr: {result.stderr[:300]}")
        return findings
    except subprocess.TimeoutExpired:
        logger.warning(f"[nuclei] timeout for {fqdn}")
        return []
    except FileNotFoundError:
        logger.error("[nuclei] not installed or not in PATH")
        return []
    except Exception as e:
        logger.error(f"[nuclei] error: {e}")
        return []


@shared_task(bind=True, name="app.tasks.scan_tasks.run_full_scan", max_retries=2)
def run_full_scan(self, domain_id: str) -> dict:
    db = SessionLocal()
    try:
        domain = db.query(Domain).filter(Domain.id == uuid.UUID(domain_id)).first()
        if not domain:
            return {"error": "domain not found"}

        job = ScanJob(
            domain_id=domain.id,
            celery_task_id=self.request.id or "",
            status=ScanStatus.running,
            started_at=utcnow(),
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        logger.info(f"Starting scan job {job.id} for {domain.fqdn}")

        try:
            subdomains = _run_subdomain_scan(domain.fqdn)
            _save_findings(db, str(job.id), subdomains)

            ports = _run_port_scan(domain.fqdn)
            _save_findings(db, str(job.id), ports)

            vulns = _run_vuln_scan(domain.fqdn)
            _save_findings(db, str(job.id), vulns)

            job.status = ScanStatus.completed
            job.finished_at = utcnow()
            domain.last_scanned_at = utcnow()
            db.commit()

            total = len(subdomains) + len(ports) + len(vulns)
            logger.info(f"Scan {job.id} complete — {total} findings")
            return {"job_id": str(job.id), "findings": total}

        except Exception as exc:
            job.status = ScanStatus.failed
            job.error_message = str(exc)
            job.finished_at = utcnow()
            db.commit()
            raise self.retry(exc=exc, countdown=60)

    finally:
        db.close()


@shared_task(name="app.tasks.scan_tasks.schedule_due_scans")
def schedule_due_scans() -> dict:
    from datetime import timedelta
    db = SessionLocal()
    try:
        now = utcnow()
        domains = db.query(Domain).filter(Domain.is_active == True).all()  # noqa
        queued = 0
        for domain in domains:
            if domain.last_scanned_at is None:
                due = True
            else:
                due = (domain.last_scanned_at + timedelta(hours=domain.scan_interval_hours)) <= now
            if due:
                try:
                    run_full_scan.delay(str(domain.id))
                    queued += 1
                except Exception:
                    pass
        logger.info(f"schedule_due_scans: queued {queued} scans")
        return {"queued": queued}
    finally:
        db.close()