from __future__ import annotations

import json
from dataclasses import dataclass

import requests

from wazuh_pull.config import Settings


def prepare_alarms(findings: list[dict], settings: Settings) -> list[dict]:
    return [
        {
            "finding_id": f"{finding['asset_id']}_{finding['vulnerability_id']}",
            "servidor": finding["asset_hostname"],
            "ip": finding["asset_ip"],
            "TipoAlarma": settings.backend_alarm_type,
            "Local": settings.backend_local,
            "fechaalarma": finding["fechaalarma"],
            "asset_id": finding["asset_id"],
            "vulnerability_id": finding["vulnerability_id"],
            "vulnerability_title": finding["vulnerability_title"],
            "severity": finding["severity"].capitalize(),
            "cvss_score": finding["cvss_score"],
            "cves": finding["cves"],
            "source": "wazuh",
        }
        for finding in findings
    ]


@dataclass(frozen=True)
class Receipt:
    accepted: bool
    replayed: bool = False
    error: str = ""
    retryable: bool = False


class BackendAlarmClient:
    def __init__(self, settings: Settings, session: requests.Session) -> None:
        self.settings = settings
        self.session = session

    def post_snapshot(self, body: str) -> Receipt:
        try:
            response = self.session.post(
                self.settings.backend_url,
                data=body.encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=self.settings.backend_timeout,
                verify=self.settings.backend_verify,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            retryable = isinstance(exc, (requests.Timeout, requests.ConnectionError)) and not isinstance(
                exc, (requests.exceptions.SSLError, requests.exceptions.ProxyError),
            )
            return Receipt(False, error=f"Error de transporte: {type(exc).__name__}", retryable=retryable)
        try:
            result = response.json()
        except ValueError:
            result = None
        if not 200 <= response.status_code < 300:
            data = result.get("data") if isinstance(result, dict) else None
            accepted = data.get("registros_exitosos") if isinstance(data, dict) else None
            if type(accepted) is int and accepted > 0:
                return Receipt(False, error="El backend reportó registros aceptados sin confirmar el snapshot completo")
            return Receipt(
                False, error=f"El backend respondió HTTP {response.status_code}",
                retryable=response.status_code in {408, 429, 500, 502, 503, 504},
            )
        if not isinstance(result, dict):
            return Receipt(False, error="El backend devolvió un recibo inválido")

        payload = json.loads(body)
        if result.get("success") is True:
            data = result.get("data")
            expected = len(payload["alarms"])
            if (
                isinstance(data, dict)
                and data.get("snapshot_id") == payload["snapshot_id"]
                and all(type(data.get(key)) is int and data[key] == expected
                        for key in ("total_alarmas", "registros_exitosos"))
                and data.get("errores") in (None, [])
            ):
                return Receipt(True)
            return Receipt(False, error="El backend devolvió un recibo parcial, incompleto o de otro snapshot")
        if _confirmed_duplicate(result, payload):
            return Receipt(True, replayed=True)
        return Receipt(False, error="El backend no confirmó la entrega completa")


def _confirmed_duplicate(response: dict, payload: dict) -> bool:
    """Accept a replay only when the receiver confirms every exact key."""
    data = response.get("data")
    expected = {alarm["finding_id"] for alarm in payload["alarms"]}
    snapshot_id = payload["snapshot_id"]
    if response.get("success") is not False or not expected or not isinstance(data, dict):
        return False
    if (
        data.get("snapshot_id") != snapshot_id
        or type(data.get("total_alarmas")) is not int
        or data["total_alarmas"] != len(expected)
        or data.get("registros_exitosos", 0) != 0
    ):
        return False
    errors = data.get("errores")
    if not isinstance(errors, list) or len(errors) != len(expected):
        return False
    for item in errors:
        if not isinstance(item, dict):
            return False
        identity = item.get("finding_id")
        if not isinstance(identity, str) or identity not in expected:
            return False
        message = f"Ya existe un registro con la combinación finding_id='{identity}' y snapshot_id='{snapshot_id}'"
        if item.get("error") != message:
            return False
        expected.remove(identity)
    return not expected
