from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import dotenv_values

ALERT_INDEX = "wazuh-alerts-*"


@dataclass(frozen=True)
class Settings:
    indexer_url: str
    indexer_user: str
    indexer_password: str = field(repr=False)
    index: str
    source_id: str
    indexer_verify: str | bool
    api_url: str
    api_user: str
    api_password: str = field(repr=False)
    api_verify: str | bool
    source_timeout: int
    page_size: int
    poll_interval: int
    backend_enabled: bool
    backend_url: str
    backend_local: str
    backend_alarm_type: str
    backend_verify: str | bool
    backend_timeout: int
    backend_allow_empty: bool
    delivery_state: Path
    retry_seconds: int
    retry_max_seconds: int
    ack_retention_days: int
    alert_lookback: int
    alert_overlap: int

    @property
    def uses_alerts(self) -> bool:
        return self.index == ALERT_INDEX

    def validate_source(self) -> None:
        if not (self.indexer_url and self.indexer_user and self.indexer_password):
            raise ValueError("Configura WAZUH_INDEXER_URL, WAZUH_INDEXER_USER y WAZUH_INDEXER_PASSWORD.")
        if not self.uses_alerts and not re.fullmatch(r"wazuh-states-vulnerabilities-[a-z0-9_.-]+", self.index):
            raise ValueError("WAZUH_INDEX debe ser wazuh-alerts-* o un índice concreto de vulnerabilidades.")
        if any((self.api_url, self.api_user, self.api_password)) and not all(
            (self.api_url, self.api_user, self.api_password)
        ):
            raise ValueError("Configura la URL y ambas credenciales de WAZUH_API para enriquecer IP.")


def load_settings(env_file: Path) -> Settings:
    values = {**dotenv_values(env_file), **os.environ}

    def value(name: str, default: str = "") -> str:
        return (values.get(name) or default).strip()

    def positive_int(name: str, default: int) -> int:
        raw = value(name, str(default))
        if not raw.isascii() or not raw.isdecimal() or len(raw) > 9 or int(raw) < 1:
            raise ValueError(f"{name} debe ser un entero positivo.")
        return int(raw)

    def enabled(name: str) -> bool:
        raw = value(name, "false").lower()
        if raw not in {"true", "false", "1", "0"}:
            raise ValueError(f"{name} debe ser true o false.")
        return raw in {"true", "1"}

    def https_url(name: str, default: str = "") -> str:
        url = value(name, default).rstrip("/")
        if url:
            parsed = urlsplit(url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.query or parsed.fragment:
                raise ValueError(f"{name} debe ser una URL HTTPS sin credenciales, query ni fragmento.")
            if parsed.port == 0:
                raise ValueError(f"{name} tiene un puerto inválido.")
        return url

    source_id = value("WAZUH_SOURCE_ID", "mifibra")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", source_id):
        raise ValueError("WAZUH_SOURCE_ID debe tener hasta 40 letras minúsculas, dígitos o guiones.")
    retry_seconds = positive_int("DELIVERY_RETRY_SECONDS", 60)
    retry_max = positive_int("DELIVERY_RETRY_MAX_SECONDS", 3600)
    if retry_max < retry_seconds:
        raise ValueError("DELIVERY_RETRY_MAX_SECONDS debe ser mayor o igual al retraso inicial.")
    page_size = positive_int("WAZUH_PAGE_SIZE", 500)
    if page_size > 10_000:
        raise ValueError("WAZUH_PAGE_SIZE debe ser menor o igual a 10000.")

    return Settings(
        indexer_url=https_url("WAZUH_INDEXER_URL"),
        indexer_user=value("WAZUH_INDEXER_USER"),
        indexer_password=values.get("WAZUH_INDEXER_PASSWORD") or "",
        index=value("WAZUH_INDEX", ALERT_INDEX),
        source_id=source_id,
        indexer_verify=value("WAZUH_INDEXER_CA_BUNDLE") or True,
        api_url=https_url("WAZUH_API_URL"),
        api_user=value("WAZUH_API_USER"),
        api_password=values.get("WAZUH_API_PASSWORD") or "",
        api_verify=value("WAZUH_API_CA_BUNDLE") or True,
        source_timeout=positive_int("WAZUH_TIMEOUT", 30),
        page_size=page_size,
        poll_interval=positive_int("POLL_INTERVAL_SECONDS", 3600),
        backend_enabled=enabled("BACKEND_ENABLED"),
        backend_url=https_url("BACKEND_URL"),
        backend_local=value("BACKEND_LOCAL", "Mi Fibra"),
        backend_alarm_type=value("BACKEND_ALARM_TYPE", "Alarma de seguridad de Wazuh x TXDXSecure"),
        backend_verify=value("BACKEND_CA_BUNDLE") or True,
        backend_timeout=positive_int("BACKEND_TIMEOUT", 180),
        backend_allow_empty=enabled("BACKEND_ALLOW_EMPTY"),
        delivery_state=Path(value("DELIVERY_STATE_PATH", "runtime/wazuh/delivery.sqlite3")),
        retry_seconds=retry_seconds,
        retry_max_seconds=retry_max,
        ack_retention_days=positive_int("DELIVERY_ACK_RETENTION_DAYS", 90),
        alert_lookback=positive_int("WAZUH_ALERT_LOOKBACK_SECONDS", 7200),
        alert_overlap=positive_int("WAZUH_ALERT_OVERLAP_SECONDS", 300),
    )
