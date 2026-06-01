"""
Scan tasks — real scanner implementations.
subfinder → subdomain enumeration
nmap      → port + service detection
nuclei    → vulnerability scanning
"""
from __future__ import annotations

import json
import os
import queue
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone

from celery import shared_task
from celery.utils.log import get_task_logger

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.models import Domain, Finding, ScanJob, ScanStatus, Severity

logger = get_task_logger(__name__)

NUCLEI_TEMPLATES = "/nuclei-templates"

# Default dirs when NUCLEI_SCAN_MODE=dirs (2 dirs ≈ minutes, not hours)
NUCLEI_SCAN_DIRS = [
    "/nuclei-templates/http/vulnerabilities",
    "/nuclei-templates/http/exposures",
]

# Narrow root for tags mode — do not scan all 13k templates
NUCLEI_TAGS_ROOT = "/nuclei-templates/http/vulnerabilities"


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


def _probe_tcp_ports(fqdn: str, ports: tuple[int, ...] = (80, 443)) -> set[int]:
    """TCP connect probe — works in Docker/Railway where raw nmap SYN scans often fail."""
    open_ports: set[int] = set()
    for port in ports:
        try:
            with socket.create_connection((fqdn, port), timeout=5):
                open_ports.add(port)
        except OSError:
            continue
    return open_ports


def _nuclei_target_urls(fqdn: str, port_findings: list[dict] | None = None) -> list[str]:
    """Build nuclei -u targets from open ports; avoid HTTPS-only when only HTTP serves."""
    ports: set[int] = set()
    if port_findings:
        for f in port_findings:
            p = f.get("port")
            if isinstance(p, int):
                ports.add(p)

    if not ports:
        ports = _probe_tcp_ports(fqdn)
        if ports:
            logger.info(f"[nuclei] tcp probe open ports for {fqdn}: {sorted(ports)}")

    urls: list[str] = []
    if ports:
        if 80 in ports:
            urls.append(f"http://{fqdn}")
        if 443 in ports:
            urls.append(f"https://{fqdn}")
    elif settings.nuclei_fallback_targets.lower() == "both":
        urls = [f"http://{fqdn}", f"https://{fqdn}"]
    else:
        urls = [f"http://{fqdn}"]

    seen: set[str] = set()
    ordered: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    return ordered


def _nuclei_templates_root() -> str | None:
    if os.path.isdir(NUCLEI_TEMPLATES):
        return NUCLEI_TEMPLATES
    return None


def _count_nuclei_templates(root: str) -> int:
    count = 0
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            if name.endswith((".yaml", ".yml")):
                count += 1
    return count


def _nuclei_template_args() -> list[str]:
    root = _nuclei_templates_root()
    if not root:
        logger.error(f"[nuclei] template root missing: {NUCLEI_TEMPLATES}")
        return []

    mode = settings.nuclei_scan_mode.strip().lower()
    if mode == "tags":
        tags = settings.nuclei_scan_tags.strip()
        tag_root = NUCLEI_TAGS_ROOT if os.path.isdir(NUCLEI_TAGS_ROOT) else root
        if tags:
            return ["-t", tag_root, "-tags", tags]

    scan_dirs = [d for d in NUCLEI_SCAN_DIRS if os.path.isdir(d)]
    if not scan_dirs:
        scan_dirs = [root]
    args: list[str] = []
    for d in scan_dirs:
        args += ["-t", d]
    return args


def _execute_nuclei(cmd: list[str], fqdn: str, timeout_sec: int) -> tuple[list[dict], str, bool]:
    """
    Run nuclei with a wall-clock timeout.
    Reading stdout line-by-line blocks when nuclei is silent; use a reader thread
    and poll the queue so we can kill the process on time.
    """
    findings: list[dict] = []
    deadline = time.monotonic() + timeout_sec
    line_queue: queue.Queue[str | None] = queue.Queue()
    stderr_chunks: list[str] = []
    timed_out = False

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    def read_stdout() -> None:
        try:
            if proc.stdout is None:
                return
            for line in proc.stdout:
                line_queue.put(line)
        finally:
            line_queue.put(None)

    def read_stderr() -> None:
        try:
            if proc.stderr is None:
                return
            stderr_chunks.append(proc.stderr.read())
        except Exception:
            pass

    threading.Thread(target=read_stdout, daemon=True).start()
    threading.Thread(target=read_stderr, daemon=True).start()

    last_progress = time.monotonic()
    while True:
        now = time.monotonic()
        if now > deadline:
            timed_out = True
            proc.kill()
            logger.warning(
                f"[nuclei] timeout ({timeout_sec}s) for {fqdn} — "
                f"keeping {len(findings)} findings"
            )
            break

        if now - last_progress >= 60:
            logger.info(
                f"[nuclei] still running for {fqdn} "
                f"({int(now - (deadline - timeout_sec))}s elapsed, "
                f"{len(findings)} findings so far)"
            )
            last_progress = now

        try:
            line = line_queue.get(timeout=1.0)
        except queue.Empty:
            if proc.poll() is not None:
                # Drain any remaining lines after process exit
                while True:
                    try:
                        extra = line_queue.get_nowait()
                    except queue.Empty:
                        break
                    if extra is None:
                        break
                    extra = extra.strip()
                    if extra.startswith("{"):
                        findings.extend(_parse_nuclei_jsonl(extra, fqdn))
                break
            continue

        if line is None:
            break
        line = line.strip()
        if line.startswith("{"):
            findings.extend(_parse_nuclei_jsonl(line, fqdn))

    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

    return findings, "".join(stderr_chunks)[:500], timed_out


def _parse_nuclei_jsonl(stdout: str, default_target: str) -> list[dict]:
    findings: list[dict] = []
    for line in stdout.strip().splitlines():
        if not line or not line.lstrip().startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = data.get("info") or {}
        severity = str(info.get("severity", "info")).lower()
        name = info.get("name", "Unknown")
        matched_at = data.get("matched-at") or data.get("host") or default_target
        description = info.get("description", "")

        cve_id = ""
        classification = info.get("classification") or {}
        raw_cve = classification.get("cve-id")
        if isinstance(raw_cve, list) and raw_cve:
            cve_id = str(raw_cve[0])
        elif isinstance(raw_cve, str) and raw_cve:
            cve_id = raw_cve

        findings.append({
            "finding_type": "vuln",
            "target": matched_at,
            "severity": severity,
            "title": name,
            "description": description,
            "cve_id": cve_id,
            "raw_output": line[:1000],
        })
    return findings


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
                # -sT -Pn: TCP connect + skip ping — required in most cloud containers
                "nmap", "-sT", "-Pn", "-sV", "--open", "-T4",
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
        if not findings and result.stderr:
            logger.warning(f"[nmap] 0 ports for {fqdn}; stderr={result.stderr[:400]!r}")
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


def _run_vuln_scan(fqdn: str, port_findings: list[dict] | None = None) -> list[dict]:
    target_urls = _nuclei_target_urls(fqdn, port_findings)
    template_args = _nuclei_template_args()
    logger.info(
        f"[nuclei] scanning {fqdn} targets={target_urls} "
        f"mode={settings.nuclei_scan_mode!r} templates={template_args[:4]!r}..."
    )

    root = _nuclei_templates_root()
    if not template_args or not root:
        logger.warning("[nuclei] no templates — run: nuclei -update-templates -ud /nuclei-templates")
        return []

    tpl_count = _count_nuclei_templates(root)
    logger.info(f"[nuclei] template root {root} ({tpl_count} yaml files)")
    if tpl_count == 0:
        logger.warning("[nuclei] 0 template files under /nuclei-templates")
        return []

    cmd: list[str] = ["nuclei"]
    for url in target_urls:
        cmd += ["-u", url]
    cmd += template_args
    cmd += [
        "-severity", "low,medium,high,critical",
        "-jsonl",
        "-silent",
        "-ss", "template-spray",
        "-timeout", str(settings.nuclei_request_timeout),
        "-rate-limit", "100",
        "-bulk-size", "25",
        "-concurrency", "25",
        "-max-host-error", "50",
        "-duc",
    ]

    try:
        findings, stderr, timed_out = _execute_nuclei(
            cmd, fqdn, settings.nuclei_subprocess_timeout
        )
        if stderr and not findings:
            logger.warning(f"[nuclei] stderr: {stderr[:500]!r}")
        elif stderr:
            logger.info(f"[nuclei] stderr: {stderr[:300]}")

        logger.info(f"[nuclei] found {len(findings)} vulns for {fqdn}")
        return findings
    except FileNotFoundError:
        logger.error("[nuclei] not installed or not in PATH")
        return []
    except Exception as e:
        logger.error(f"[nuclei] error: {e}")
        return []


@shared_task(
    bind=True,
    name="app.tasks.scan_tasks.run_full_scan",
    max_retries=2,
    soft_time_limit=settings.scan_task_soft_time_limit,
    time_limit=settings.scan_task_time_limit,
)
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

            vulns = _run_vuln_scan(domain.fqdn, ports)
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
