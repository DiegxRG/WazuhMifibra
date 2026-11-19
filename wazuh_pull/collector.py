from __future__ import annotations

import math
import re
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address

from wazuh_pull.client import SourceError

SEVERITY = {"critical": 2, "high": 1}
EXCLUDED_SEVERITIES = {"medium", "moderate", "low", "info", "informational", "none", "unknown"}
ACTIVE_STATES = {"active", "detected", "open", "vulnerable"}
RESOLVED_STATES = {"closed", "fixed", "remediated", "resolved", "solved"}


@dataclass(frozen=True)
class Occurrence:
    agent_id: str
    hostname: str
    ip: str
    vulnerability_id: str
    title: str
    severity: str
    cvss: float | None
    detected_at: str
    package: dict[str, str]


@dataclass(frozen=True)
class Collection:
    documents: int
    findings: list[dict]


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _object(value) -> dict:
    return value if isinstance(value, dict) else {}


def _valid_ip(*values) -> str:
    for value in values:
        candidates = sorted(filter(None, map(_text, value))) if isinstance(value, list) else [_text(value)]
        for candidate in candidates:
            try:
                address = ip_address(candidate)
            except ValueError:
                continue
            if "%" not in candidate and not address.is_unspecified and not address.is_multicast:
                return str(address)
    return ""


def _date(value) -> str:
    parsed = datetime.fromisoformat(_text(value))
    if parsed.tzinfo is None:
        raise ValueError("se esperaba una fecha de detección con zona horaria")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _score(value) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("CVSS inválido")
    score = float(value)
    if not math.isfinite(score) or not 0 <= score <= 10:
        raise ValueError("CVSS fuera del rango 0–10")
    return score


def _normalize(hit: dict) -> Occurrence | None:
    doc = _object(_object(hit).get("_source"))
    vulnerability = _object(doc.get("vulnerability"))
    severity = _text(vulnerability.get("severity")).casefold()
    if severity in EXCLUDED_SEVERITIES:
        return None
    if severity not in SEVERITY:
        raise ValueError("vulnerability.severity ausente o desconocida")
    state = _text(vulnerability.get("status") or vulnerability.get("state")).casefold()
    if state in RESOLVED_STATES:
        return None
    if state and state not in ACTIVE_STATES:
        raise ValueError("estado de vulnerabilidad desconocido")
    agent = _object(doc.get("agent"))
    agent_id = _text(agent.get("id"))
    vulnerability_id = _text(vulnerability.get("id")).upper()
    if not re.fullmatch(r"[0-9]+", agent_id):
        raise ValueError("agent.id ausente o inválido")
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9.-]*", vulnerability_id):
        raise ValueError("vulnerability.id ausente o inválido")
    package = _object(doc.get("package"))
    title = _text(vulnerability.get("title"))
    package_name = _text(package.get("name"))
    return Occurrence(
        agent_id=agent_id, hostname=_text(agent.get("name")),
        ip=_valid_ip(agent.get("ip"), _object(doc.get("host")).get("ip")),
        vulnerability_id=vulnerability_id,
        title=title or (f"{vulnerability_id} - {package_name}" if package_name else vulnerability_id),
        severity=severity, cvss=_score(_object(vulnerability.get("score")).get("base")),
        detected_at=_date(vulnerability.get("detected_at")),
        package={field: _text(package.get(field)) for field in ("name", "version", "architecture", "type")},
    )


def _normalize_alert(hit: dict) -> Occurrence | None:
    doc = _object(_object(hit).get("_source"))
    vuln = _object(_object(doc.get("data")).get("vulnerability"))
    if _text(vuln.get("status")).casefold() != "active" or _text(vuln.get("severity")).casefold() not in SEVERITY:
        return None
    return _normalize({"_source": {
        "agent": doc.get("agent"),
        "package": vuln.get("package"),
        "vulnerability": {
            "id": vuln.get("cve"), "severity": vuln.get("severity"), "title": vuln.get("title"),
            "score": vuln.get("score"), "detected_at": doc.get("timestamp"),
        },
    }})


def _priority(item: Occurrence) -> tuple:
    cvss = item.cvss if item.cvss is not None else -1
    return -SEVERITY[item.severity], -cvss, item.title, item.hostname, item.ip, item.detected_at


def collect(
    hits: Iterable[dict],
    source_id: str,
    get_agents: Callable[[set[str]], dict[str, dict]],
    *,
    from_alerts: bool = False,
) -> Collection:
    groups = defaultdict(list)
    ips: dict[str, set[str]] = defaultdict(set)
    documents = 0
    normalize = _normalize_alert if from_alerts else _normalize
    for documents, hit in enumerate(hits, start=1):
        try:
            occurrence = normalize(hit)
        except (TypeError, ValueError, OverflowError) as exc:
            raise SourceError(f"Documento {documents} de Wazuh inválido: {exc}.") from exc
        if occurrence is not None:
            groups[occurrence.agent_id, occurrence.vulnerability_id].append(occurrence)
            if occurrence.ip:
                ips[occurrence.agent_id].add(occurrence.ip)

    missing_ips = {agent_id for agent_id, _ in groups if not ips.get(agent_id)}
    agents = get_agents(missing_ips) if missing_ips else {}
    findings = []
    for (agent_id, vulnerability_id), items in sorted(groups.items()):
        representative = min(items, key=_priority)
        metadata = _object(agents.get(agent_id))
        ip = min(ips[agent_id], default="") or _valid_ip(metadata.get("ip"), metadata.get("registerIP"))
        if not ip:
            raise SourceError("Un agente con hallazgos críticos o altos carece de IP utilizable.")
        asset_id = f"wazuh-{source_id}-{agent_id}"
        cves = [vulnerability_id] if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", vulnerability_id) else []
        hostname = representative.hostname or min((item.hostname for item in items if item.hostname), default="")
        findings.append({
            "asset_id": asset_id,
            "asset_hostname": hostname or _text(metadata.get("name")) or ip,
            "asset_ip": ip,
            "vulnerability_id": vulnerability_id,
            "vulnerability_title": representative.title,
            "severity": representative.severity,
            "cvss_score": representative.cvss,
            "cves": cves,
            "fechaalarma": min(item.detected_at for item in items),
            "occurrences": [
                {"package": item.package, "severity": item.severity, "cvss_score": item.cvss,
                 "detected_at": item.detected_at}
                for item in items
            ],
        })
    return Collection(documents, findings)
