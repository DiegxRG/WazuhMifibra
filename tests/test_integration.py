from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest
import requests

from wazuh_pull.backend_client import BackendAlarmClient, prepare_alarms
from wazuh_pull.cli import main
from wazuh_pull.client import SourceError, WazuhClient
from wazuh_pull.collector import collect
from wazuh_pull.config import ALERT_INDEX, load_settings
from wazuh_pull.delivery import alert_window, deliver

FIXTURE = Path(__file__).parent / "fixtures" / "inventory.json"


@pytest.fixture
def sample():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture
def settings(monkeypatch, tmp_path):
    for name in ("BACKEND_ALLOW_EMPTY", "BACKEND_ENABLED", "WAZUH_SOURCE_ID"):
        monkeypatch.delenv(name, raising=False)
    return replace(
        load_settings(tmp_path / ".env"),
        index="wazuh-states-vulnerabilities-example",
        indexer_url="https://indexer.example",
        backend_url="https://backend.example/guarda_alarma.php",
        delivery_state=tmp_path / "delivery.sqlite3",
        retry_seconds=1,
        retry_max_seconds=30,
    )


def response(body, status=200):
    reply = Mock(status_code=status)
    reply.json.return_value = body
    return reply


def findings_from(sample, settings):
    return collect(sample["hits"], settings.source_id, lambda _ids: {"002": sample["agent"]}).findings


def test_sample_with_backend_enabled_is_offline(monkeypatch, tmp_path):
    monkeypatch.setenv("BACKEND_ENABLED", "true")
    monkeypatch.setenv("WAZUH_SOURCE_ID", "mifibra")
    state = tmp_path / "delivery.sqlite3"
    monkeypatch.setenv("DELIVERY_STATE_PATH", str(state))
    session = Mock(side_effect=AssertionError("offline flow opened an HTTP session"))
    monkeypatch.setattr("wazuh_pull.cli.requests.Session", session)
    preview = tmp_path / "preview.json"
    assert main(["--input", str(FIXTURE), "--output", str(preview)]) == 0
    assert not state.exists()
    result = json.loads(preview.read_text(encoding="utf-8"))
    envelope = result["request_preview"]
    assert set(envelope) == {"snapshot_id", "alarms"}
    critical, high = envelope["alarms"]
    assert len(critical) == 13
    assert critical["finding_id"] == "wazuh-mifibra-002_CVE-2026-12345"
    assert critical["ip"] == "192.0.2.42"
    assert critical["cves"] == ["CVE-2026-12345"]
    assert critical["severity"] == "Critical"
    assert critical["cvss_score"] == 9.8
    assert critical["fechaalarma"] == "2026-11-18 20:10:31"
    assert high["severity"] == "High"
    assert high["fechaalarma"] == "2026-11-19 00:21:00"
    assert len(result["findings"][0]["occurrences"]) == 2


def test_filter_and_fail_instead_of_publishing_on_invalid_critical(sample, settings):
    medium = copy.deepcopy(sample["hits"][2])
    medium["_source"]["vulnerability"]["severity"] = "Medium"
    fixed = copy.deepcopy(sample["hits"][1])
    fixed["_source"]["vulnerability"]["status"] = "Solved"
    sample["hits"] = [medium, fixed, sample["hits"][0]]
    assert [item["severity"] for item in findings_from(sample, settings)] == ["high"]
    del sample["hits"][2]["_source"]["vulnerability"]["detected_at"]
    with pytest.raises(SourceError, match="Documento 3"):
        findings_from(sample, settings)


def test_indexer_pages_and_releases_latest_scroll_id(sample, settings):
    def page(hits, cursor):
        return {"_scroll_id": cursor, "timed_out": False, "_shards": {"failed": 0},
                "hits": {"total": {"value": 3, "relation": "eq"}, "hits": hits}}

    http = Mock()
    http.request.side_effect = [
        response(page(sample["hits"][:1], "first")),
        response(page(sample["hits"][1:], "second")),
        response({"succeeded": True}),
    ]
    assert list(WazuhClient(settings, http).vulnerability_hits()) == sample["hits"]
    cleanup = http.request.call_args
    assert cleanup.args[0] == "DELETE"
    assert cleanup.kwargs["json"] == {"scroll_id": ["second"]}


def test_missing_indexer_pages_fail_instead_of_treating_inventory_as_empty(sample, settings):
    http = Mock()
    http.request.side_effect = [
        response({"_scroll_id": "cursor", "timed_out": False, "_shards": {"failed": 0},
                  "hits": {"total": {"value": 3, "relation": "eq"}, "hits": sample["hits"][:1]}}),
        response({"timed_out": False, "_shards": {"failed": 0}, "hits": {"hits": []}}),
        response({"succeeded": True}),
    ]
    with pytest.raises(SourceError, match="antes del total"):
        list(WazuhClient(settings, http).vulnerability_hits())
    assert http.request.call_args.args[0] == "DELETE"


def test_collector_requests_only_agents_without_ip(sample, settings):
    get_agents = Mock(return_value={"002": sample["agent"]})
    result = collect(sample["hits"], settings.source_id, get_agents)
    get_agents.assert_called_once_with({"002"})
    assert len(result.findings) == 2


def test_manager_looks_up_only_requested_agents_in_batches(settings, monkeypatch):
    http = Mock()
    settings = replace(settings, api_url="https://manager.example", api_user="fixture", api_password="fixture")
    monkeypatch.setattr("wazuh_pull.client.AGENT_LOOKUP_BATCH_SIZE", 2)
    http.request.side_effect = [
        response({"data": {"token": "test-token"}}),
        response({"error": 0, "data": {"total_affected_items": 2, "affected_items": [{"id": "002"}, {"id": "003"}]}}),
        response({"error": 0, "data": {"total_affected_items": 1, "affected_items": [{"id": "005"}]}}),
    ]
    assert list(WazuhClient(settings, http).agents({"005", "002", "003"})) == ["002", "003", "005"]
    batches = [call.kwargs["params"]["agents_list"] for call in http.request.call_args_list[1:]]
    assert batches == ["002,003", "005"]


def test_manager_rejects_partial_agent_results(settings):
    http = Mock()
    settings = replace(settings, api_url="https://manager.example", api_user="fixture", api_password="fixture")
    http.request.side_effect = [
        response({"data": {"token": "test-token"}}),
        response({"error": 0, "data": {"total_affected_items": 1, "affected_items": [{"id": "002"}]}}),
    ]
    with pytest.raises(SourceError, match="todos los agentes"):
        WazuhClient(settings, http).agents({"002", "003"})


@pytest.mark.parametrize(("complete", "no_backend"), [(True, False), (False, False), (True, True)])
def test_live_cli_honors_capture_completeness_and_no_backend(sample, monkeypatch, tmp_path, complete, no_backend):
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.example")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "fixture")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "fixture")
    monkeypatch.setenv("WAZUH_INDEX", sample["index"])
    monkeypatch.setenv("WAZUH_SOURCE_ID", "mifibra")
    for name in ("WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BACKEND_ENABLED", "true")
    monkeypatch.setenv("BACKEND_URL", "https://backend.example/guarda_alarma.php")
    state = tmp_path / "delivery.sqlite3"
    monkeypatch.setenv("DELIVERY_STATE_PATH", str(state))
    backend_http = MagicMock()
    backend_http.__enter__.return_value = backend_http
    backend_http.post.return_value = response({"success": True})
    source_http = MagicMock()
    source_http.__enter__.return_value = source_http
    hit = sample["hits"][2]
    source_http.request.return_value = response({
        "timed_out": False, "_shards": {"failed": 0 if complete else 1},
        "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [hit]},
    })
    monkeypatch.setattr("wazuh_pull.cli.requests.Session", Mock(side_effect=[backend_http, source_http]))

    args = ["--once", "--env-file", str(tmp_path / ".env")]
    if no_backend:
        original_state = b"existing delivery state"
        state.write_bytes(original_state)
        preview = tmp_path / "preview.json"
        args.extend(["--no-backend", "--output", str(preview)])

    assert main(args) == (0 if complete else 1)
    assert state.exists() is (complete or no_backend)
    assert backend_http.post.call_count == int(complete and not no_backend)
    if no_backend:
        assert state.read_bytes() == original_state
        payload = json.loads(preview.read_text(encoding="utf-8"))["request_preview"]
        assert payload["alarms"][0]["finding_id"] == "wazuh-mifibra-003_CVE-2026-12346"
    elif complete:
        payload = json.loads(backend_http.post.call_args.kwargs["data"])
        assert payload["alarms"][0]["finding_id"] == "wazuh-mifibra-003_CVE-2026-12346"


def test_outbox_deduplicates_date_and_order_but_captures_package_changes(sample, settings, monkeypatch):
    settings = replace(settings, backend_enabled=True)
    http = Mock()
    http.post.return_value = response({"success": True})
    backend = BackendAlarmClient(settings, http)
    monkeypatch.setattr("wazuh_pull.delivery.time.time", lambda: 1795120000)
    findings = findings_from(sample, settings)
    alarms = prepare_alarms(findings, settings)
    assert deliver(backend, alarms=alarms, findings=findings, started_at=1)["sent"] == 1
    alarms[0]["fechaalarma"] = "2026-11-20 10:11:12"
    assert deliver(backend, alarms=alarms[::-1], findings=findings[::-1], started_at=2)["snapshot"] == "sin_cambios"
    assert http.post.call_count == 1
    findings[0]["occurrences"][0]["package"]["version"] = "2.0"
    assert deliver(backend, alarms=alarms, findings=findings, started_at=3)["sent"] == 1
    bodies = [json.loads(call.kwargs["data"]) for call in http.post.call_args_list]
    assert bodies[0]["snapshot_id"] != bodies[1]["snapshot_id"]
    assert [len(body["alarms"]) for body in bodies] == [2, 2]
    assert deliver(backend, alarms=[], findings=[], started_at=4)["snapshot"] == "snapshot_vacio_retenido"
    assert http.post.call_count == 2


def test_outbox_replays_identical_body_after_restart_in_fifo(sample, settings, monkeypatch):
    settings = replace(settings, backend_enabled=True)
    clock = [1795120000]
    monkeypatch.setattr("wazuh_pull.delivery.time.time", lambda: clock[0])
    findings = findings_from(sample, settings)
    alarms = prepare_alarms(findings, settings)
    first_http = Mock()
    first_http.post.side_effect = requests.Timeout()
    initial = deliver(BackendAlarmClient(settings, first_http), alarms=alarms, findings=findings, started_at=1)
    assert initial["pending"] == 1
    original_body = first_http.post.call_args.kwargs["data"]
    payload = json.loads(original_body)
    snapshot_id = payload["snapshot_id"]
    errors = []
    for alarm in payload["alarms"]:
        identity = alarm["finding_id"]
        errors.append({"finding_id": identity, "error":
                       f"Ya existe un registro con la combinación finding_id='{identity}' y snapshot_id='{snapshot_id}'"})
    receipt = {"success": False, "data": {"snapshot_id": snapshot_id, "total_alarmas": 2, "errores": errors}}

    retry_http = Mock()
    retry_http.post.side_effect = [response(receipt), response({"success": True})]
    backend = BackendAlarmClient(settings, retry_http)
    alarms[0]["cvss_score"] = 10.0
    assert deliver(backend, alarms=alarms, findings=findings, started_at=2)["pending"] == 2
    retry_http.post.assert_not_called()
    clock[0] += 1
    replay = deliver(backend)
    assert replay["sent"] == 2 and replay["replayed"] == 1 and replay["pending"] == 0
    assert retry_http.post.call_args_list[0].kwargs["data"] == original_body
    assert retry_http.post.call_args_list[1].kwargs["data"] != original_body


def test_partial_receipt_keeps_the_snapshot_pending(sample, settings):
    http = Mock()
    http.post.return_value = response({"success": True, "data": {"registros_exitosos": 1}})
    settings = replace(settings, backend_enabled=True)
    findings = findings_from(sample, settings)
    result = deliver(BackendAlarmClient(settings, http), alarms=prepare_alarms(findings, settings),
                     findings=findings, started_at=1)
    assert result["sent"] == 0 and result["pending"] == 1
    assert "parcial" in result["error"]


def test_enabled_delivery_requires_an_explicit_backend_url(settings):
    http = Mock()
    settings = replace(settings, backend_enabled=True, backend_url="")
    with pytest.raises(ValueError, match="BACKEND_URL"):
        deliver(BackendAlarmClient(settings, http))
    http.post.assert_not_called()
    assert not settings.delivery_state.exists()


def wazuh_alert(event_id, epoch, severity, *, cve="CVE-2026-12345", status="Active", level=10):
    stamp = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    return {
        "_index": "wazuh-alerts-4.x-2026.11.19",
        "_id": event_id,
        "_source": {
            "timestamp": stamp,
            "rule": {"level": level},
            "agent": {"id": "002", "name": "example-agent", "ip": "192.0.2.42"},
            "data": {"vulnerability": {
                "cve": cve, "status": status, "severity": severity,
                "title": "Vulnerabilidad de ejemplo", "score": {"base": "9.8" if severity == "Critical" else "8.1"},
                "package": {"name": "example-lib", "version": "1.0", "architecture": "x86_64"},
            }},
        },
    }


def search_results(hits, *, total=None, failed=0):
    return response({
        "timed_out": False, "_shards": {"failed": failed},
        "hits": {"total": {"value": len(hits) if total is None else total, "relation": "eq"}, "hits": hits},
    })


def test_event_preview_uses_vulnerability_severity_and_event_timestamp(settings, tmp_path):
    sample_path = tmp_path / "alerts.json"
    preview = tmp_path / "preview.json"
    events = [
        wazuh_alert("1", 1795119000, "High", level=10),
        wazuh_alert("2", 1795119060, "Critical", level=13),
        wazuh_alert("3", 1795119120, "Critical", cve="CVE-2026-12346", status="Solved"),
        {"_index": "wazuh-alerts-4.x-2026.11.19", "_id": "4", "_source": {"rule": {"level": 15}}},
    ]
    sample_path.write_text(json.dumps({"hits": {"hits": events}}), encoding="utf-8")
    assert main(["--input", str(sample_path), "--output", str(preview)]) == 0
    payload = json.loads(preview.read_text(encoding="utf-8"))
    assert len(payload["request_preview"]["alarms"]) == 1
    alarm = payload["request_preview"]["alarms"][0]
    assert alarm["severity"] == "Critical" and alarm["cvss_score"] == 9.8
    assert alarm["finding_id"] == "wazuh-mifibra-002_CVE-2026-12345"
    assert len(alarm) == 13
    assert alarm["fechaalarma"] == datetime.fromtimestamp(1795119000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def test_alert_search_splits_bounded_ranges_using_only_search(settings):
    settings = replace(settings, index=ALERT_INDEX, page_size=1)
    first = wazuh_alert("1", 1795119000, "High")
    last = wazuh_alert("2", 1795119001, "Critical")
    http = Mock()
    http.request.side_effect = [search_results([first], total=2), search_results([first]), search_results([last])]
    assert list(WazuhClient(settings, http).alert_hits(1795119000000, 1795119002000)) == [first, last]
    queries = [call.kwargs["json"]["query"]["bool"]["filter"] for call in http.request.call_args_list]
    assert [(filters[0]["range"]["timestamp"]["gte"], filters[0]["range"]["timestamp"]["lt"]) for filters in queries] == [
        (1795119000000, 1795119002000), (1795119000000, 1795119001000), (1795119001000, 1795119002000),
    ]
    assert all(call.args == ("GET", "https://indexer.example/wazuh-alerts-*/_search") for call in http.request.call_args_list)


def test_alert_runs_keep_progress_on_overlap_and_retry_exact_body(monkeypatch, tmp_path):
    for name, value in {
        "WAZUH_INDEX": ALERT_INDEX,
        "WAZUH_INDEXER_URL": "https://indexer.example",
        "WAZUH_INDEXER_USER": "fixture",
        "WAZUH_INDEXER_PASSWORD": "fixture",
        "BACKEND_ENABLED": "true",
        "BACKEND_URL": "https://backend.example/guarda_alarma.php",
        "BACKEND_ALLOW_EMPTY": "true",
        "DELIVERY_STATE_PATH": str(tmp_path / "delivery.sqlite3"),
        "DELIVERY_RETRY_SECONDS": "1",
        "WAZUH_ALERT_OVERLAP_SECONDS": "300",
    }.items():
        monkeypatch.setenv(name, value)
    env_file = tmp_path / ".env"
    settings = load_settings(env_file)
    clock = [1795120000]
    monkeypatch.setattr("wazuh_pull.delivery.time.time", lambda: clock[0])
    first = wazuh_alert("same", clock[0] - 10, "High")
    late = wazuh_alert("late", clock[0] - 20, "Critical", cve="CVE-2026-12346")

    backend = MagicMock()
    backend.__enter__.return_value = backend
    backend.post.side_effect = [requests.Timeout(), response({"success": True}), response({"success": True})]
    indexer = MagicMock()
    indexer.__enter__.return_value = indexer
    indexer.request.side_effect = [
        search_results([first]), search_results([], failed=1), search_results([late, first]), search_results([first, late]),
    ]
    monkeypatch.setattr("wazuh_pull.cli.requests.Session", Mock(side_effect=[backend, indexer] * 4))
    args = ["--once", "--env-file", str(env_file)]
    assert main(args) == 1
    original_request = backend.post.call_args.kwargs["data"]

    clock[0] += 15
    assert main(args) == 1
    assert alert_window(settings, clock[0] * 1000).previous_end == 1795120000000
    assert backend.post.call_args.kwargs["data"] == original_request

    clock[0] += 15
    assert main(args) == 0
    new_payload = json.loads(backend.post.call_args.kwargs["data"])
    assert [alarm["vulnerability_id"] for alarm in new_payload["alarms"]] == ["CVE-2026-12346"]

    clock[0] += 15
    assert main(args) == 0
    assert alert_window(settings, (clock[0] + 1) * 1000).previous_end == clock[0] * 1000
    assert backend.post.call_count == 3
