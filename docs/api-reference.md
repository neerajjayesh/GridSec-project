# REST API reference

[Documentation index](index.md) · [OpenAPI JSON](reference/openapi.json)

## Availability and base URL

The HTTP implementation is `core/rest_api.py`, using Python's standard-library `HTTPServer`. It can be started through the core `GridSecRESTServer` or `IntegrationManager`. The desktop REST Start button currently calls a missing convenience method, so use the documented core example to explore the API.

```text
http://127.0.0.1:8080/api/v1
```

The documentation example uses port **18080** to distinguish it from application defaults:

```powershell
.\.venv\Scripts\python.exe docs/examples/serve_api.py
```

It serves one synthetic incident without starting protocol simulators or enabling remote attacks. Copy the bearer token printed locally. Stop with `Ctrl+C`. Do not run multiple API examples in the same Python process: state is module-global.

## Authentication

All implemented GET routes except `/api/v1/status` and all POST routes require:

```http
Authorization: Bearer YOUR_LOCAL_API_TOKEN
```

Initial state enables authentication and generates a token with `secrets.token_hex(16)`. `set_api_key()` changes it; `disable_auth()` and `enable_auth()` control enforcement. Setting an empty token does **not** itself disable auth, despite older comments suggesting otherwise.

The token is shared across server instances and logged at INFO when starting the server. There is no TLS, account model, role separation, expiry, rate limiting, or durable audit log. Bind loopback for local work and protect token-bearing logs. See [Security](../SECURITY.md).

## Routes

| Method and path | Input | Response |
|---|---|---|
| `GET /api/v1/status` | None; public | Tool/version/time/auth plus integration status |
| `GET /api/v1/simulation` | None | Status callback result without the tool envelope |
| `GET /api/v1/topology` | None | Latest topology callback snapshot, or `{}` |
| `GET /api/v1/attacks/current` | None | Attack callback result, or `{}` |
| `GET /api/v1/incidents` | `limit` default 100; optional `proto` | `{count, total, incidents}` |
| `GET /api/v1/packets/recent` | `limit` default 50 | `{count, packets}` |
| `GET /api/v1/export/stix` | None | JSON attachment `gridsec_stix2.json` |
| `GET /api/v1/export/csv` | None | CSV attachment `gridsec_incidents.csv` |
| `GET /api/v1/export/pcap` | None | PCAP attachment `gridsec_capture.pcap`, or 404 |
| `GET /api/v1/events` | None | Server-Sent Events stream |
| `GET /api/v1/docs` | None | Authenticated embedded HTML help |
| `POST /api/v1/attack/enable` | JSON `type` and optional `params` | `{success, attack_type}` |
| `POST /api/v1/attack/disable` | Empty object accepted | `{success: true, message}` |
| `OPTIONS` | Preflight | 204; GET/POST/OPTIONS and Authorization/Content-Type permitted |

Paths have trailing slashes removed before dispatch. `/` becomes an empty string, so the attempted root documentation route does not resolve; use `/api/v1/docs`. There are no HTTP routes to start/stop simulation, upload topology, create incidents, set schedules, or ingest Splunk HEC data. Comments mentioning those integrations do not add endpoints.

## Status response

Illustrative manager-backed response:

```json
{
  "tool": "GridSec Sim",
  "version": "1.0.0",
  "timestamp": 1788825600.0,
  "auth": true,
  "sim_running": false,
  "session_id": "11111111-1111-4111-8111-111111111111",
  "uptime_s": 12,
  "total_incidents": 1,
  "attacked": 1,
  "integrations": {"pcap": false, "syslog": false, "rest_api": true}
}
```

`uptime_s` is time since manager construction. `total_incidents` and `attacked` count the retained history, not lifetime totals. `rest_api=true` tests manager handle presence rather than an independent health probe. In the desktop, `sim_running` can remain stale after Stop because packet callbacks set it true without resetting it there.

`/attacks/current` currently receives engine statistics from the desktop (`total_packets`, `modified_packets`, `dropped_packets`), despite its name suggesting type/parameters. A custom embedding can return a different object.

## Incident and packet queries

```powershell
$taskHeaders = @{ Authorization = 'Bearer YOUR_LOCAL_API_TOKEN' }
Invoke-RestMethod 'http://127.0.0.1:18080/api/v1/status'
Invoke-RestMethod 'http://127.0.0.1:18080/api/v1/incidents?limit=10' -Headers $taskHeaders
Invoke-RestMethod 'http://127.0.0.1:18080/api/v1/packets/recent?limit=10' -Headers $taskHeaders
```

Linux equivalent:

```bash
curl -H 'Authorization: Bearer YOUR_LOCAL_API_TOKEN' \
  'http://127.0.0.1:18080/api/v1/incidents?limit=10'
```

Results preserve chronological order within the last N retained entries. `limit` has no validated upper/lower bound: `limit=0` returns the entire retained list due to Python slicing, negative values have slice semantics, and nonintegers generally yield 500. Use positive integers.

The incident `proto` filter has a known mismatch: it looks for `proto`, while manager incident records use `protocol`. With the standard manager, a nonempty protocol filter returns no matches. Fetch without it and filter `incident.protocol` client-side.

See [Data formats](data-formats.md) for incident and packet field dictionaries. The manager retains 10,000 incidents and 1,000 packet summaries. There is no cursor, durable sequence number, or guaranteed complete export after rotation.

## Remote attack endpoints

Request shape:

```json
{"type": "NOISE", "params": {"noise_std": 5.0}}
```

The correct parameter is `noise_std`; older embedded help uses the ineffective key `std_dev`.

`IntegrationManager.set_attack_hooks(enable_fn, disable_fn)` must connect the request to an engine. The desktop does not install these hooks. Without a hook, enable returns `success=false`; disable can return success while changing no engine state. A 200 response is not sufficient confirmation that a remote attack took effect.

Supported engine type strings appear in [Attacks](attacks.md). The HTTP layer itself does not validate enum membership, parameter ranges, or schedule fields. Custom hooks must validate data, manage concurrency, and report actual outcome. The example server deliberately leaves hooks unset.

## SSE

```bash
curl --no-buffer -H 'Authorization: Bearer YOUR_LOCAL_API_TOKEN' \
  'http://127.0.0.1:18080/api/v1/events'
```

The stream starts with a comment, sends `: keepalive` comments after about 30 idle seconds, and can emit:

```text
event: incident
data: {"status":"attacked","attack_type":"NOISE"}

```

Actual event data is a full incident object. The manager broadcasts only newly recorded `attacked`/`dropped` incidents. There is no initial replay, event ID, or Last-Event-ID support. Each subscriber queue has a capacity of 100; full queues are removed from broadcast delivery.

**Current concurrency limit:** HTTPServer processes requests serially. A live SSE connection can block other API requests and delay shutdown. Use polling for routine access and disconnect SSE clients before stopping the server. The fixed example incident was recorded before clients connect, so it will not arrive retrospectively via SSE.

## Errors and response behavior

| Code | Observed meaning |
|---:|---|
| 200 | Handler completed; inspect `success` for attack commands |
| 204 | OPTIONS response |
| 400 | Missing attack `type` |
| 401 | Missing or incorrect bearer token |
| 404 | Unknown path or unavailable PCAP |
| 500 | Exception in GET handler, including invalid numeric limit |

Unauthorized JSON contains `error` and an authorization hint. JSON responses use UTF-8 and permissive CORS `*`. Malformed JSON is converted to `{}` by POST handling. Other malformed POST structures or hook exceptions are not consistently converted to structured errors. Clients should tolerate a connection failure as well as JSON error responses.

Source: [HTTP handler/server](../core/rest_api.py), [manager callbacks](../core/integration_manager.py), [desktop state wiring](../gui/main_window.py).
