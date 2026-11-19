# Wazuh-MiFibra

Extrae eventos de detección de vulnerabilidades críticas y altas de Wazuh y los prepara para el mismo receptor Mi Fibra / TXDXSecure que usa OpenVAS.

| Módulo | Responsabilidad |
| --- | --- |
| `client.py` | Obtiene los agentes autorizados del Manager y lee sus detecciones en `wazuh-alerts-*` por ventanas de tiempo. |
| `collector.py` | Valida la captura y agrupa por agente y vulnerabilidad. Conserva las ocurrencias por paquete. |
| `backend_client.py` | Construye los 13 campos de alarma y valida la confirmación HTTP del receptor. |
| `delivery.py` | Guarda el avance de lectura y deduplica eventos. Conserva en SQLite el cuerpo y el orden de entrega. |
| `cli.py` | Ejecuta una muestra local, una captura en vivo, el servicio periódico o los reintentos pendientes. |

## Probar con una muestra

Desde la raíz del proyecto, con Python 3.11 o posterior:

```powershell
python -m pip install -r requirements.txt
python main.py --input tests/fixtures/inventory.json --output runtime/wazuh/preview-example.json
```

La muestra ficticia de inventario tiene tres documentos y produce dos alarmas. Uno de los CVE aparece en dos paquetes del mismo agente. El modo `--input` funciona sin conexiones ni SQLite. Acepta un objeto con `hits` o una respuesta con `hits.hits` y reconoce los eventos por su campo `_index`. Para enriquecer IP desde la muestra, acepta `agent` con un objeto o `agents` con un arreglo.

## Validar contra Wazuh

Completa el archivo local `.env` a partir de `.env.example`. Configura la URL y la cuenta de lectura del Indexer, `WAZUH_AGENT_GROUP` con el grupo autorizado de Mi Fibra y `WAZUH_API_*` con una cuenta del Manager que pueda listar los agentes de ese grupo. Usa un `WAZUH_SOURCE_ID` estable y distinto para cada despliegue Wazuh, ya que forma parte de la identidad de sus agentes. Las conexiones usan HTTPS con verificación de certificado. Los parámetros `*_CA_BUNDLE` apuntan a los PEM de las CA cuando corresponda.

```powershell
python main.py --once --no-backend --output runtime/wazuh/preview-live.json
```

Cada captura valida la pertenencia al grupo con el Manager y limita la búsqueda en el Indexer a esos ID de agente. Una respuesta incompleta o un evento de otro grupo en la respuesta bloquean la captura. La consulta selecciona eventos `Active` con `data.vulnerability.severity` crítica o alta. Divide la ventana cuando los resultados exceden el tamaño de página y comprueba el total y los errores de shards. El conector agrupa las detecciones nuevas por agente y CVE y usa la IP registrada en el Manager cuando el evento carece de IP. El modo `--no-backend` genera una vista previa de la ventana inicial sin avanzar la cola ni enviar al receptor.

## Entrega

El contrato de salida es un POST con `snapshot_id` UTC y `alarms`. Cada alarma usa `source="wazuh"`, `Local="Mi Fibra"` por defecto y `cves` como arreglo. Un ejemplo de identidad es `wazuh-mifibra-002_CVE-2026-12345`. Cada envío desde alertas representa un lote de detecciones nuevas para el NOC.

La primera captura revisa hasta 90 días de eventos `Active` y `Solved` (`WAZUH_ALERT_REVIEW_HISTORY_SECONDS`) y prepara los casos de los últimos 30 días (`WAZUH_ALERT_LOOKBACK_SECONDS`). Excluye un par equipo y CVE cuando todos sus paquetes observados tienen un `Solved` posterior que coincide. Una detección posterior o una coincidencia ambigua mantiene el caso en revisión. La vista previa marca el lote inicial como `por_verificar` y lista por separado los críticos más antiguos. Los datos de revisión quedan fuera del contrato de 13 campos. La lista se basa en eventos y el inventario vigente permite confirmar el estado.

Las capturas siguientes reanudan desde la última ventana completa con cinco minutos de solapamiento (`WAZUH_ALERT_OVERLAP_SECONDS`) para recuperar eventos tardíos. Se deduplica por índice y documento. Un evento distinto del mismo equipo y CVE puede generar otro aviso con el mismo `finding_id`. Una ventana sin detecciones nuevas avanza el cursor sin publicar una captura vacía. Los `Solved` se usan en la revisión inicial y los ciclos incrementales envían detecciones nuevas.

`BACKEND_ENABLED` parte en `false`. Para habilitar el envío, configura la URL HTTPS del receptor en `BACKEND_URL` en el archivo local `.env`. SQLite guarda en la misma transacción los eventos vistos, el avance y el cuerpo del lote. El reintento usa el mismo identificador y cuerpo. Una búsqueda incompleta deja el cursor donde estaba.

`python main.py --retry-pending` vuelve a intentar la cola sin consultar Wazuh. `python main.py` corre en modo periódico usando `POLL_INTERVAL_SECONDS`. Mantén la base de entrega en disco local.

Si se configura un índice concreto `wazuh-states-vulnerabilities-*`, el conector conserva el modo de inventario y envía capturas completas cuando cambia su contenido. `BACKEND_ALLOW_EMPTY` aplica a ese modo.

Para ejecutar las pruebas locales con pytest instalado, usa `python -m pytest -q`.
