from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from wazuh_pull.client import SourceError, alert_key
from wazuh_pull.collector import SEVERITY

Package = tuple[str, str, str]


@dataclass(frozen=True)
class Alert:
    timestamp: datetime
    status: str
    severity: str
    package: Package
    hit: dict


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _parse_event(hit: dict) -> tuple[tuple[str, str], Alert]:
    try:
        doc = hit["_source"]
        vulnerability = doc["data"]["vulnerability"]
        asset = doc["agent"]["id"]
        cve = _text(vulnerability["cve"]).upper()
        status = _text(vulnerability["status"]).casefold()
        severity = _text(vulnerability.get("severity")).casefold()
        timestamp = datetime.fromisoformat(doc["timestamp"])
        package = vulnerability.get("package") or {}
        if not isinstance(package, dict) or not cve or not asset or not timestamp.tzinfo or status not in {"active", "solved"}:
            raise ValueError("Campos de ciclo de vida inválidos.")
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise SourceError("No se pudo interpretar un evento Active o Solved de la revisión inicial.") from exc
    identity = (
        _text(package.get("name")).casefold(),
        _text(package.get("version")),
        _text(package.get("architecture")).casefold(),
    )
    return (asset, cve), Alert(timestamp, status, severity, identity, hit)


def _compatible(left: Package, right: Package) -> bool:
    return bool(left[0]) and left[0] == right[0] and all(
        not a or not b or a == b for a, b in zip(left[1:], right[1:])
    )


def _order(alert: Alert) -> tuple:
    return alert.timestamp, SEVERITY.get(alert.severity, 0), alert_key(alert.hit)


def _unresolved_alerts(timeline: list[Alert], priority: list[Alert]) -> list[Alert]:
    active = defaultdict(list)
    priority_by_package = defaultdict(list)
    for alert in timeline:
        if alert.status == "active":
            active[alert.package].append(alert)
    for alert in priority:
        priority_by_package[alert.package].append(alert)

    solved = defaultdict(list)
    ambiguous = defaultdict(list)
    for alert in timeline:
        if alert.status != "solved":
            continue
        if not alert.package[0]:
            for package in active:
                ambiguous[package].append(alert.timestamp)
        elif all(alert.package) and alert.package in active:
            solved[alert.package].append(alert.timestamp)
        else:
            candidates = [package for package in active if _compatible(package, alert.package)]
            if len(candidates) == 1:
                solved[candidates[0]].append(alert.timestamp)
            else:
                for package in candidates:
                    ambiguous[package].append(alert.timestamp)

    unresolved = []
    for package, alerts in priority_by_package.items():
        last_active = max(alert.timestamp for alert in active[package])
        last_solved = max(solved[package], default=last_active)
        # Require a later, unambiguous Solved for each observed affected package.
        if last_solved <= last_active or any(timestamp >= last_solved for timestamp in ambiguous[package]):
            unresolved.append(max(alerts, key=_order))
    return unresolved


def initial_alert_review(hits: Iterable[dict], priority_from_ms: int) -> tuple[list[dict], dict]:
    boundary = datetime.fromtimestamp(priority_from_ms / 1000, timezone.utc)
    timelines = defaultdict(list)
    total_events = 0
    for hit in hits:
        key, alert = _parse_event(hit)
        timelines[key].append(alert)
        total_events += 1

    recent_hits = []
    older_critical = []
    recent_pairs = 0
    resolved_recent = 0
    for (agent, cve), timeline in sorted(timelines.items()):
        priority = [alert for alert in timeline if alert.status == "active" and alert.severity in SEVERITY]
        if not priority:
            continue
        latest = max(priority, key=_order)
        unresolved = _unresolved_alerts(timeline, priority)
        if latest.timestamp >= boundary:
            recent_pairs += 1
            if unresolved:
                recent_hits.extend(alert.hit for alert in unresolved)
            else:
                resolved_recent += 1
        elif latest.severity == "critical" and unresolved:
            older_critical.append({
                "agent_id": agent, "vulnerability_id": cve,
                "ultima_deteccion": latest.timestamp.astimezone(timezone.utc).isoformat(),
            })

    return recent_hits, {
        "estado": "por_verificar",
        "inicio_ventana_inicial": boundary.isoformat(),
        "eventos_revisados": total_events,
        "pares_recientes": recent_pairs,
        "pares_recientes_con_solved_posterior": resolved_recent,
        "criticos_antiguos": older_critical,
    }
