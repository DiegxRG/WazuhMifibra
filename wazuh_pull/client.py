from __future__ import annotations

import logging
from collections.abc import Iterator

import requests

from wazuh_pull.config import Settings

log = logging.getLogger(__name__)
SCROLL_KEEP_ALIVE = "2m"
AGENT_LOOKUP_BATCH_SIZE = 100
GROUP_PAGE_SIZE = 500


class SourceError(RuntimeError):
    """Wazuh did not return a complete, usable response."""


class WazuhClient:
    def __init__(self, settings: Settings, session: requests.Session) -> None:
        self.settings = settings
        self.session = session

    def _request(self, method: str, url: str, *, verify: str | bool, label: str, **kwargs) -> dict:
        try:
            response = self.session.request(
                method,
                url,
                timeout=self.settings.source_timeout,
                verify=verify,
                allow_redirects=False,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise SourceError(f"{label}: {type(exc).__name__}.") from exc
        if not 200 <= response.status_code < 300:
            raise SourceError(f"{label}: HTTP {response.status_code}.")
        try:
            body = response.json()
        except ValueError as exc:
            raise SourceError(f"{label}: respuesta sin JSON válido.") from exc
        if not isinstance(body, dict):
            raise SourceError(f"{label}: se esperaba un objeto JSON.")
        return body

    def vulnerability_hits(self, allowed_agents: set[str] | None = None) -> Iterator[dict]:
        settings = self.settings
        auth = (settings.indexer_user, settings.indexer_password)
        scroll_url = f"{settings.indexer_url}/_search/scroll"
        scroll_id = None
        seen = set()
        query = {"size": settings.page_size, "sort": ["_doc"], "track_total_hits": True}
        if allowed_agents is not None:
            query["query"] = {"terms": {"agent.id": sorted(allowed_agents)}}
        try:
            body = self._request(
                "GET", f"{settings.indexer_url}/{settings.index}/_search",
                verify=settings.indexer_verify, label="Búsqueda de vulnerabilidades",
                auth=auth, params={"scroll": SCROLL_KEEP_ALIVE, "allow_partial_search_results": "false"},
                json=query,
            )
            scroll_id = body.get("_scroll_id")
            hit_count = body.get("hits")
            total = hit_count.get("total") if isinstance(hit_count, dict) else None
            if isinstance(total, dict):
                total = total.get("value") if total.get("relation") == "eq" else None
            if type(total) is not int or total < 0:
                raise SourceError("El Indexer no devolvió un total exacto de vulnerabilidades.")

            while True:
                shards = body.get("_shards")
                hits = body.get("hits")
                page = hits.get("hits") if isinstance(hits, dict) else None
                if (body.get("timed_out") is not False or body.get("terminated_early") is True
                    or not isinstance(shards, dict) or shards.get("failed") != 0
                    or not isinstance(page, list)):
                    raise SourceError("El Indexer devolvió una página incompleta.")
                for hit in page:
                    if not isinstance(hit, dict) or hit.get("_index") != settings.index:
                        raise SourceError("El documento no pertenece al índice configurado.")
                    identity = hit.get("_id")
                    if not isinstance(identity, str) or not identity or identity in seen:
                        raise SourceError("El Indexer devolvió un documento sin ID o repetido.")
                    _check_agent_scope(hit, allowed_agents)
                    seen.add(identity)
                    if len(seen) > total:
                        raise SourceError("El Indexer devolvió más documentos que el total anunciado.")
                    yield hit
                if len(seen) == total:
                    return
                if not page or not isinstance(scroll_id, str) or not scroll_id:
                    raise SourceError("La paginación terminó antes del total anunciado.")
                body = self._request(
                    "POST", scroll_url, verify=settings.indexer_verify, label="Página del Indexer",
                    auth=auth, json={"scroll": SCROLL_KEEP_ALIVE, "scroll_id": scroll_id},
                )
                scroll_id = body.get("_scroll_id") or scroll_id
        finally:
            if isinstance(scroll_id, str) and scroll_id:
                try:
                    self._request("DELETE", scroll_url, verify=settings.indexer_verify,
                                  label="Liberar búsqueda", auth=auth, json={"scroll_id": [scroll_id]})
                except SourceError as exc:
                    log.warning("%s El contexto de búsqueda expirará automáticamente.", exc)

    def alert_hits(
        self, start: int, end: int, allowed_agents: set[str] | None = None, *, include_solved: bool = False,
    ) -> Iterator[dict]:
        """Read bounded millisecond windows using only the Search API."""
        if start >= end:
            return
        settings = self.settings
        url = f"{settings.indexer_url}/{settings.index}/_search"
        if include_solved:
            event_filters = [{"bool": {"should": [
                {"match_phrase": {"data.vulnerability.status": status}} for status in ("Active", "Solved")
            ], "minimum_should_match": 1}}]
        else:
            event_filters = [
                {"match_phrase": {"data.vulnerability.status": "Active"}},
                {"bool": {"should": [
                    {"match_phrase": {"data.vulnerability.severity": "Critical"}},
                    {"match_phrase": {"data.vulnerability.severity": "High"}},
                ], "minimum_should_match": 1}},
            ]
        agent_filter = [{"terms": {"agent.id": sorted(allowed_agents)}}] if allowed_agents is not None else []
        windows = [(start, end)]
        seen = set()
        while windows:
            lower, upper = windows.pop()
            # A single millisecond cannot be split further.
            size = settings.page_size if upper - lower > 1 else 10_000
            filters = [
                {"range": {"timestamp": {"gte": lower, "lt": upper, "format": "epoch_millis"}}},
                {"exists": {"field": "data.vulnerability.cve"}},
                *event_filters,
                *agent_filter,
            ]
            body = self._request(
                "GET", url, verify=settings.indexer_verify, label="Búsqueda de alertas Wazuh",
                auth=(settings.indexer_user, settings.indexer_password),
                params={"allow_partial_search_results": "false"},
                json={
                    "query": {"bool": {"filter": filters}},
                    "_source": [
                        "timestamp", "agent.id", "agent.name", "agent.ip", "data.vulnerability.cve",
                        "data.vulnerability.status", "data.vulnerability.severity", "data.vulnerability.title",
                        "data.vulnerability.score.base", "data.vulnerability.package",
                    ],
                    "size": size,
                    "track_total_hits": True,
                },
            )
            hits_data = body.get("hits")
            page = hits_data.get("hits") if isinstance(hits_data, dict) else None
            total = hits_data.get("total") if isinstance(hits_data, dict) else None
            if isinstance(total, dict):
                total = total.get("value") if total.get("relation") == "eq" else None
            shards = body.get("_shards")
            if (body.get("timed_out") is not False or body.get("terminated_early") is True
                or not isinstance(shards, dict) or shards.get("failed") != 0
                or not isinstance(page, list) or type(total) is not int or total < 0):
                raise SourceError("La búsqueda de alertas devolvió una respuesta incompleta.")
            if total > size:
                if upper - lower <= 1:
                    raise SourceError("El volumen de alertas en un milisegundo excede el máximo de búsqueda.")
                middle = lower + (upper - lower) // 2
                windows.extend([(middle, upper), (lower, middle)])
                continue
            if len(page) != total:
                raise SourceError("La cantidad de alertas no coincide con el total anunciado.")
            for hit in page:
                key = alert_key(hit)
                _check_agent_scope(hit, allowed_agents)
                if key in seen:
                    raise SourceError("La búsqueda devolvió una alerta repetida dentro de la ventana.")
                seen.add(key)
                yield hit

    def agents(self, agent_ids: set[str]) -> dict[str, dict]:
        settings = self.settings
        if not settings.api_url or not agent_ids:
            return {}
        headers = self._api_headers()
        agents = {}
        ordered_ids = sorted(agent_ids)
        for start in range(0, len(ordered_ids), AGENT_LOOKUP_BATCH_SIZE):
            batch = ordered_ids[start:start + AGENT_LOOKUP_BATCH_SIZE]
            expected = set(batch)
            body = self._request(
                "GET", f"{settings.api_url}/agents", verify=settings.api_verify,
                label="Consulta de agentes", headers=headers,
                params={"agents_list": ",".join(batch), "select": "id,name,ip,registerIP", "limit": len(batch)},
            )
            records, total = self._agent_records(body)
            if len(records) != len(batch) or total != len(batch):
                raise SourceError("El Wazuh Manager no devolvió todos los agentes solicitados.")
            for agent in records:
                agent_id = agent.get("id") if isinstance(agent, dict) else None
                if not isinstance(agent_id, str) or agent_id not in expected:
                    raise SourceError("El Wazuh Manager devolvió un agente inesperado o repetido.")
                expected.remove(agent_id)
                agents[agent_id] = agent
        return agents

    def _api_headers(self) -> dict[str, str]:
        settings = self.settings
        body = self._request(
            "POST", f"{settings.api_url}/security/user/authenticate",
            auth=(settings.api_user, settings.api_password),
            verify=settings.api_verify, label="Autenticación del Manager",
        )
        data = body.get("data")
        token = data.get("token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise SourceError("El Wazuh Manager no devolvió un token.")
        return {"Authorization": f"Bearer {token}"}

    @staticmethod
    def _agent_records(body: dict) -> tuple[list, int]:
        data = body.get("data")
        if body.get("error") != 0 or not isinstance(data, dict) or data.get("total_failed_items", 0) != 0:
            raise SourceError("El Wazuh Manager devolvió una consulta de agentes incompleta.")
        records = data.get("affected_items")
        total = data.get("total_affected_items")
        if not isinstance(records, list) or type(total) is not int or total < len(records):
            raise SourceError("El Wazuh Manager devolvió una cantidad de agentes inconsistente.")
        return records, total

    def group_agents(self) -> dict[str, dict]:
        settings = self.settings
        group = settings.agent_group
        headers = self._api_headers()
        agents = {}
        total = None
        while total is None or len(agents) < total:
            body = self._request(
                "GET", f"{settings.api_url}/groups/{group}/agents", verify=settings.api_verify,
                label="Consulta del grupo autorizado", headers=headers,
                params={"select": "id,name,group,ip,registerIP", "sort": "id",
                        "limit": GROUP_PAGE_SIZE, "offset": len(agents)},
            )
            records, page_total = self._agent_records(body)
            if (total is not None and total != page_total) or not records or len(agents) + len(records) > page_total:
                raise SourceError("El grupo autorizado está vacío o su paginación es incompleta.")
            total = page_total
            for agent in records:
                agent_id = agent.get("id") if isinstance(agent, dict) else None
                groups = agent.get("group") if isinstance(agent, dict) else None
                if (not isinstance(agent_id, str) or not agent_id.isascii() or not agent_id.isdecimal()
                    or agent_id in agents or not isinstance(groups, list) or group not in groups):
                    raise SourceError("El Wazuh Manager devolvió un agente inesperado o repetido en el grupo.")
                agents[agent_id] = agent
        return agents


def alert_key(hit: dict) -> str:
    index = hit.get("_index") if isinstance(hit, dict) else None
    identity = hit.get("_id") if isinstance(hit, dict) else None
    if (not isinstance(index, str) or not index.startswith("wazuh-alerts-")
        or not isinstance(identity, str) or not identity):
        raise SourceError("El evento Wazuh carece de índice o ID válido.")
    return f"{index}/{identity}"


def _check_agent_scope(hit: dict, allowed_agents: set[str] | None) -> None:
    if allowed_agents is None:
        return
    source = hit.get("_source")
    agent = source.get("agent") if isinstance(source, dict) else None
    agent_id = agent.get("id") if isinstance(agent, dict) else None
    if not isinstance(agent_id, str) or agent_id not in allowed_agents:
        raise SourceError("El Indexer devolvió un evento ajeno al grupo autorizado.")
