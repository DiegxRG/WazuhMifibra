from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import tempfile
import time
from collections.abc import Iterator
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import requests

from wazuh_pull.backend_client import BackendAlarmClient, prepare_alarms
from wazuh_pull.client import SourceError, WazuhClient, alert_key
from wazuh_pull.collector import collect
from wazuh_pull.config import Settings, load_settings
from wazuh_pull.delivery import AlertWindow, alert_window, deliver

log = logging.getLogger(__name__)


def _read_sample(path: Path) -> tuple[list[dict], dict[str, dict]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("La muestra debe ser un objeto JSON con hits.")
    hits = data.get("hits")
    if isinstance(hits, dict):
        hits = hits.get("hits")
    if not isinstance(hits, list):
        raise ValueError("La muestra debe contener un arreglo hits o hits.hits.")
    agent_records = data.get("agents", [])
    if not isinstance(agent_records, list):
        raise ValueError("agents debe ser un arreglo de objetos.")
    if "agent" in data:
        agent_records = [*agent_records, data["agent"]]
    agents = {}
    for record in agent_records:
        agent_id = record.get("id") if isinstance(record, dict) else None
        if not isinstance(agent_id, str) or not agent_id or agent_id in agents:
            raise ValueError("La muestra contiene un agente sin ID o repetido.")
        agents[agent_id] = record
    return hits, agents


def _write_preview(path: Path, findings: list[dict], alarms: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False)
    temp_path = Path(temporary.name)
    try:
        with temporary:
            json.dump(
                {
                    "request_preview": {
                        "snapshot_id": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "alarms": alarms,
                    },
                    "findings": findings,
                },
                temporary,
                indent=2,
                ensure_ascii=False,
            )
            temporary.write("\n")
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def _log_delivery(result: dict) -> int:
    log.info(
        "snapshot=%s confirmados=%s reenvios_confirmados=%s pendientes=%s",
        result["snapshot"], result["sent"], result["replayed"], result["pending"],
    )
    if result["error"]:
        log.error("%s", result["error"])
    if result["snapshot"] == "snapshot_vacio_retenido":
        log.warning("La captura vacía quedó retenida por BACKEND_ALLOW_EMPTY=false.")
    return int(bool(result["error"] or result["pending"] or result["snapshot"] == "snapshot_vacio_retenido"))


def _new_alerts(source: WazuhClient, window: AlertWindow) -> Iterator[dict]:
    with closing(source.alert_hits(window.start_ms, window.end_ms)) as hits:
        for hit in hits:
            key = alert_key(hit)
            if key in window.seen:
                continue
            try:
                raw_timestamp = hit["_source"]["timestamp"]
                timestamp = datetime.fromisoformat(raw_timestamp)
                if timestamp.tzinfo is None:
                    raise ValueError("Se esperaba una zona horaria.")
                event_ms = int(timestamp.timestamp()) * 1000 + timestamp.microsecond // 1000
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                raise SourceError("Una alerta del Indexer tiene un timestamp inválido.") from exc
            if not window.start_ms <= event_ms < window.end_ms:
                raise SourceError("El Indexer devolvió una alerta fuera de la ventana.")
            window.events[key] = event_ms
            yield hit


def _run_live(
    settings: Settings, source: WazuhClient, backend: BackendAlarmClient, *, once: bool, output: Path | None,
) -> int:
    while True:
        started_at = time.time()
        capture = {}
        status = 0
        try:
            window = alert_window(settings, int(started_at * 1000)) if settings.uses_alerts else None
            observations = _new_alerts(source, window) if window is not None else source.vulnerability_hits()
            with closing(observations) as hits:
                collection = collect(hits, settings.source_id, source.agents, from_alerts=settings.uses_alerts)
            alarms = prepare_alarms(collection.findings, settings)
            log.info("documentos=%s alarmas_criticas_y_altas=%s", collection.documents, len(alarms))
            if output:
                _write_preview(output, collection.findings, alarms)
            capture = {"alarms": alarms, "findings": collection.findings, "started_at": started_at, "window": window}
        except (SourceError, OSError, sqlite3.Error) as exc:
            log.error("Captura incompleta: %s", exc)
            status = 1
        try:
            status |= _log_delivery(deliver(backend, **capture))
        except (OSError, RuntimeError, sqlite3.Error) as exc:
            log.error("Error de entrega: %s", exc)
            status = 1
        if once:
            return status
        time.sleep(settings.poll_interval)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Integra vulnerabilidades críticas y altas de Wazuh con Mi Fibra.")
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--input", type=Path, help="Procesa una muestra JSON local sin conexiones ni escrituras en SQLite.")
    mode.add_argument("--once", action="store_true", help="Ejecuta una captura del Indexer y termina.")
    mode.add_argument("--retry-pending", action="store_true", help="Reintenta la cola local sin consultar Wazuh.")
    parser.add_argument("--no-backend", action="store_true", help="Deshabilita el envío y el estado de entrega.")
    parser.add_argument("--output", type=Path, help="Escribe un JSON local de vista previa con alarmas y hallazgos.")
    args = parser.parse_args(argv)
    if args.retry_pending and args.output:
        parser.error("--output requiere una captura o una muestra.")

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        settings = load_settings(args.env_file)
        if args.input:
            if args.output and args.output.resolve() == args.input.resolve():
                parser.error("--output debe ser distinto de --input.")
            hits, agents = _read_sample(args.input)
            from_alerts = [str(hit.get("_index", "")).startswith("wazuh-alerts-") for hit in hits if isinstance(hit, dict)]
            if any(from_alerts) and not all(from_alerts):
                raise ValueError("La muestra mezcla alertas e inventario.")
            collection = collect(hits, settings.source_id, lambda _ids: agents, from_alerts=any(from_alerts))
            alarms = prepare_alarms(collection.findings, settings)
            log.info("muestra_local documentos=%s alarmas_criticas_y_altas=%s", collection.documents, len(alarms))
            if args.output:
                _write_preview(args.output, collection.findings, alarms)
            return 0

        if args.no_backend:
            settings = replace(settings, backend_enabled=False)
        with requests.Session() as backend_session:
            backend = BackendAlarmClient(settings, backend_session)
            if args.retry_pending:
                return _log_delivery(deliver(backend))
            settings.validate_source()
            with requests.Session() as source_session:
                source = WazuhClient(settings, source_session)
                return _run_live(settings, source, backend, once=args.once, output=args.output)
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        log.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        return 130
