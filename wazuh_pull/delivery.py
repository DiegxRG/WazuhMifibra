from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from wazuh_pull.backend_client import BackendAlarmClient
from wazuh_pull.config import Settings

MAX_ATTEMPTS = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoints (
    scope TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
    started_at REAL NOT NULL, epoch INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY, scope TEXT NOT NULL, snapshot_id TEXT NOT NULL,
    body TEXT NOT NULL, context TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
    acknowledged_at REAL, last_error TEXT, delivery_status TEXT NOT NULL DEFAULT 'pending',
    UNIQUE(scope, snapshot_id)
);
CREATE INDEX IF NOT EXISTS pending_snapshots ON snapshots(scope, id)
    WHERE acknowledged_at IS NULL;
CREATE TABLE IF NOT EXISTS alert_progress (
    scope TEXT PRIMARY KEY, end_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS seen_alerts (
    scope TEXT NOT NULL, identity TEXT NOT NULL, timestamp_ms INTEGER NOT NULL,
    PRIMARY KEY(scope, identity)
);
"""


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _scope(settings: Settings) -> str:
    keys = [settings.backend_url, settings.backend_local, settings.source_id, "wazuh", settings.agent_group]
    if settings.uses_alerts:
        keys.extend([settings.indexer_url, settings.index])
    return hashlib.sha256(_json(keys).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AlertWindow:
    start_ms: int
    end_ms: int
    previous_end: int | None
    seen: frozenset[str]
    priority_from_ms: int | None = None
    events: dict[str, int] = field(default_factory=dict)


def alert_window(settings: Settings, end_ms: int) -> AlertWindow:
    path = settings.delivery_state.resolve()
    scope = _scope(settings)
    previous_end = None
    seen = frozenset()
    if settings.backend_enabled and path.is_file():
        with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=10)) as db:
            db.execute("BEGIN")
            existing = db.execute("SELECT 1 FROM sqlite_master WHERE name='alert_progress'").fetchone()
            if existing:
                previous = db.execute("SELECT end_ms FROM alert_progress WHERE scope=?", (scope,)).fetchone()
                if previous:
                    previous_end = previous[0]
                    seen = frozenset(row[0] for row in db.execute("SELECT identity FROM seen_alerts WHERE scope=?", (scope,)))
    if previous_end is None:
        return AlertWindow(
            end_ms - settings.alert_review_history * 1000, end_ms, None, seen,
            priority_from_ms=end_ms - settings.alert_lookback * 1000,
        )
    elif end_ms <= previous_end:
        # An older clock cannot move the checkpoint backwards.
        start_ms = end_ms
    else:
        start_ms = previous_end - settings.alert_overlap * 1000
    return AlertWindow(start_ms, end_ms, previous_end, seen)


def _fingerprint(alarms: list[dict], findings: list[dict]) -> str:
    ids = [alarm["finding_id"] for alarm in alarms]
    if len(set(ids)) != len(ids):
        raise ValueError("La captura contiene finding_id repetidos.")
    public = [{key: value for key, value in alarm.items() if key != "fechaalarma"} for alarm in alarms]
    packages = {
        f"{finding['asset_id']}_{finding['vulnerability_id']}": sorted({
            _json({key: value for key, value in occurrence.items() if key != "detected_at"})
            for occurrence in finding["occurrences"]
        })
        for finding in findings
    }
    canonical = _json([sorted(public, key=lambda alarm: alarm["finding_id"]), packages])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@contextmanager
def _sender_lock(path: Path) -> Iterator[None]:
    with path.open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError("Ya hay un emisor activo para este ámbito de entrega.") from exc
        # Closing the file releases the OS lock on both platforms.
        yield


@contextmanager
def _outbox(path: Path, scope: str) -> Iterator[sqlite3.Connection]:
    with _sender_lock(path.with_name(f"{path.name}.{scope}.lock")), closing(sqlite3.connect(path, timeout=10)) as db:
        os.chmod(path, 0o600)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.executescript(SCHEMA)
        with db:
            # Lock the migration across scopes sharing this database.
            db.execute("BEGIN IMMEDIATE")
            columns = {column["name"] for column in db.execute("PRAGMA table_info(snapshots)")}
            if "delivery_status" not in columns:
                db.execute("ALTER TABLE snapshots ADD COLUMN delivery_status TEXT NOT NULL DEFAULT 'pending'")
                db.execute("UPDATE snapshots SET delivery_status='acked' WHERE acknowledged_at IS NOT NULL")
        yield db


def resolve_review(settings: Settings, snapshot_id: str, *, confirmed: bool) -> None:
    if not (settings.backend_url and settings.agent_group):
        raise ValueError("Configura BACKEND_URL y WAZUH_AGENT_GROUP para identificar la cola.")
    path = settings.delivery_state.resolve()
    if not path.is_file():
        raise ValueError("La base de entrega no existe.")
    scope = _scope(settings)
    with _outbox(path, scope) as db, db:
        status = "acked" if confirmed else "retry_once"
        changed = db.execute(
            """UPDATE snapshots
               SET delivery_status=?, next_attempt=0, acknowledged_at=?,
                   last_error=CASE WHEN ? THEN NULL ELSE last_error END
               WHERE scope=? AND snapshot_id=? AND acknowledged_at IS NULL AND delivery_status='review'""",
            (status, time.time() if confirmed else None, confirmed, scope, snapshot_id),
        ).rowcount
        if not changed:
            raise ValueError("El snapshot indicado no está en revisión en esta cola.")


def _enqueue(
    db: sqlite3.Connection, scope: str, alarms: list[dict], findings: list[dict], started_at: float,
    *, deduplicate: bool = True,
) -> str:
    fingerprint = _fingerprint(alarms, findings)
    checkpoint = db.execute("SELECT * FROM checkpoints WHERE scope=?", (scope,)).fetchone()
    if checkpoint and started_at < checkpoint["started_at"]:
        return "captura_anterior"
    if deduplicate and checkpoint and checkpoint["fingerprint"] == fingerprint:
        db.execute("UPDATE checkpoints SET started_at=? WHERE scope=?", (started_at, scope))
        return "sin_cambios"

    epoch = int(time.time())
    if checkpoint:
        epoch = max(epoch, checkpoint["epoch"] + 1)
    snapshot_id = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = _json({"snapshot_id": snapshot_id, "alarms": alarms})
    db.execute(
        "INSERT INTO snapshots(scope, snapshot_id, body, context) VALUES (?, ?, ?, ?)",
        (scope, snapshot_id, body, _json(findings)),
    )
    db.execute(
        """INSERT INTO checkpoints VALUES (?, ?, ?, ?)
           ON CONFLICT(scope) DO UPDATE SET fingerprint=excluded.fingerprint,
           started_at=excluded.started_at, epoch=excluded.epoch""",
        (scope, fingerprint, started_at, epoch),
    )
    return snapshot_id


def _enqueue_alerts(
    db: sqlite3.Connection, scope: str, window: AlertWindow,
    alarms: list[dict], findings: list[dict], overlap: int,
) -> str:
    current = db.execute("SELECT end_ms FROM alert_progress WHERE scope=?", (scope,)).fetchone()
    current_end = current["end_ms"] if current else None
    if current_end != window.previous_end or (current_end is not None and current_end >= window.end_ms):
        return "captura_anterior"

    result = "sin_eventos_nuevos"
    if alarms:
        result = _enqueue(db, scope, alarms, findings, window.end_ms / 1000, deduplicate=False)
        if result == "captura_anterior":
            return result
    overlap_start = window.end_ms - overlap * 1000
    db.executemany(
        "INSERT INTO seen_alerts(scope, identity, timestamp_ms) VALUES (?, ?, ?)",
        ((scope, identity, timestamp) for identity, timestamp in window.events.items() if timestamp >= overlap_start),
    )
    db.execute("INSERT INTO alert_progress VALUES (?, ?) ON CONFLICT(scope) DO UPDATE SET end_ms=excluded.end_ms",
               (scope, window.end_ms))
    db.execute("DELETE FROM seen_alerts WHERE scope=? AND timestamp_ms<?", (scope, overlap_start))
    return result


def deliver(
    backend: BackendAlarmClient,
    *,
    alarms: list[dict] | None = None,
    findings: list[dict] | None = None,
    started_at: float | None = None,
    window: AlertWindow | None = None,
) -> dict:
    settings = backend.settings
    result = {"snapshot": None, "sent": 0, "replayed": 0, "pending": 0, "review": 0,
              "review_snapshot": None, "error": ""}
    if not settings.backend_enabled:
        return {**result, "snapshot": "envio_deshabilitado"}
    if not settings.backend_url:
        raise ValueError("Configura BACKEND_URL para habilitar el envío.")
    if not settings.agent_group:
        raise ValueError("Configura WAZUH_AGENT_GROUP para habilitar el envío.")
    if alarms is not None and (started_at is None or findings is None):
        raise ValueError("La entrega requiere los hallazgos y el inicio de la captura.")
    if alarms is not None and settings.uses_alerts != (window is not None):
        raise ValueError("La entrega de alertas requiere una ventana del Indexer.")
    path = settings.delivery_state.resolve()
    if alarms is not None and not alarms and window is None and not settings.backend_allow_empty:
        result["snapshot"] = "snapshot_vacio_retenido"
        alarms = None
    if alarms is None and not path.exists():
        return result

    scope = _scope(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _outbox(path, scope) as db:
        if alarms is not None:
            # A successful window advances only after the event IDs and outbox body are durable together.
            with db:
                if window is not None:
                    result["snapshot"] = _enqueue_alerts(db, scope, window, alarms, findings, settings.alert_overlap)
                else:
                    result["snapshot"] = _enqueue(db, scope, alarms, findings, started_at)

        while True:
            event = db.execute(
                "SELECT * FROM snapshots WHERE scope=? AND acknowledged_at IS NULL ORDER BY id LIMIT 1",
                (scope,),
            ).fetchone()
            if event is None:
                break
            if event["delivery_status"] == "review":
                result["review_snapshot"] = event["snapshot_id"]
                break
            manual = event["delivery_status"] == "retry_once"
            attempts = event["attempts"]
            if not manual and attempts >= MAX_ATTEMPTS:
                with db:
                    db.execute(
                        "UPDATE snapshots SET delivery_status='review', next_attempt=0 WHERE id=?", (event["id"],),
                    )
                result["review_snapshot"] = event["snapshot_id"]
                result["error"] = "El lote agotó sus intentos automáticos"
                break
            now = time.time()
            if event["next_attempt"] > now:
                break
            delay = min(settings.retry_seconds * 2 ** min(attempts, 30), settings.retry_max_seconds)
            can_retry = not manual and attempts + 1 < MAX_ATTEMPTS
            with db:
                # Reserve the attempt before HTTP so a restart cannot bypass the limit.
                db.execute(
                    """UPDATE snapshots SET attempts=attempts+1, delivery_status=?, next_attempt=?, last_error=?
                       WHERE id=?""",
                    ("pending" if can_retry else "review", now + delay,
                     "Proceso interrumpido o resultado del POST desconocido", event["id"]),
                )
            receipt = backend.post_snapshot(event["body"])
            now = time.time()
            with db:
                if receipt.accepted:
                    db.execute(
                        """UPDATE snapshots SET acknowledged_at=?, last_error=NULL, delivery_status='acked'
                           WHERE id=?""", (now, event["id"]),
                    )
                    result["sent"] += 1
                    result["replayed"] += int(receipt.replayed)
                else:
                    pending = can_retry and receipt.retryable
                    db.execute(
                        "UPDATE snapshots SET delivery_status=?, next_attempt=?, last_error=? WHERE id=?",
                        ("pending" if pending else "review", now + delay if pending else 0, receipt.error, event["id"]),
                    )
                    result["error"] = receipt.error
                    if not pending:
                        result["review_snapshot"] = event["snapshot_id"]
            if not receipt.accepted:
                break

        with db:
            db.execute(
                "DELETE FROM snapshots WHERE scope=? AND acknowledged_at<?",
                (scope, time.time() - settings.ack_retention_days * 86400),
            )
        counts = dict(db.execute(
            "SELECT delivery_status,count(*) FROM snapshots WHERE scope=? AND acknowledged_at IS NULL GROUP BY delivery_status",
            (scope,),
        ))
        result["pending"] = counts.get("pending", 0) + counts.get("retry_once", 0)
        result["review"] = counts.get("review", 0)
    return result
