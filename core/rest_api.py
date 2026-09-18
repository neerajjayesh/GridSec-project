"""
core/rest_api.py
=================
GridSec Sim — REST API Server (zero external dependencies)

Uses Python's built-in http.server + socketserver.

Compatible with:
  - Dragos  — poll /api/v1/incidents for alerts
  - Claroty — poll /api/v1/attacks/current for anomaly data
  - Splunk HEC — POST /api/v1/incidents from Splunk forwarder
  - Any SOAR/SIEM — REST polling or webhook

Endpoints:
  GET  /api/v1/status              Simulation + integration health
  GET  /api/v1/simulation          Detailed simulation state
  GET  /api/v1/topology            Node topology (JSON)
  GET  /api/v1/attacks/current     Active attacks + params
  GET  /api/v1/incidents           Incident log (supports ?limit=N&proto=X)
  GET  /api/v1/packets/recent      Last N captured packets
  GET  /api/v1/export/stix         STIX 2.1 bundle download
  GET  /api/v1/export/csv          CSV incident log download
  GET  /api/v1/export/pcap         pcap file download
  POST /api/v1/attack/enable       Enable attack remotely (JSON body)
  POST /api/v1/attack/disable      Disable all attacks
  GET  /api/v1/events              Server-Sent Events (SSE) live stream

Authentication:
  Bearer token via Authorization header.
  Set api_key="" to disable auth (lab/demo mode).

Example cURL:
  curl -H "Authorization: Bearer YOUR_KEY" http://127.0.0.1:8080/api/v1/status
  curl http://127.0.0.1:8080/api/v1/incidents?limit=10
"""

import json
import logging
import os
import queue
import secrets
from html import escape
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── API State (shared with handler instances) ─────────────────────────────────

class APIState:
    """Shared mutable state accessible to all request handler instances."""

    def __init__(self):
        self.api_key:      str  = secrets.token_hex(16)
        self.auth_enabled: bool = True
        self.stop_event = threading.Event()

        # Data stores (set by IntegrationManager)
        self.get_status:     Optional[Callable[[], dict]] = None
        self.get_topology:   Optional[Callable[[], dict]] = None
        self.get_attacks:    Optional[Callable[[], dict]] = None
        self.get_incidents:  Optional[Callable[[], List[dict]]] = None
        self.get_packets:    Optional[Callable[[], List[dict]]] = None
        self.enable_attack:  Optional[Callable[[str, dict], bool]] = None
        self.disable_attack: Optional[Callable[[], None]] = None
        self.get_stix:       Optional[Callable[[], dict]] = None
        self.get_csv:        Optional[Callable[[], str]]  = None
        self.get_pcap_path:  Optional[Callable[[], str]]  = None

        # Server-Sent Events subscriber queues
        self._sse_clients: List[queue.Queue] = []
        self._sse_lock     = threading.Lock()

    def add_sse_client(self) -> queue.Queue:
        q = queue.Queue(maxsize=100)
        with self._sse_lock:
            self._sse_clients.append(q)
        return q

    def remove_sse_client(self, q: queue.Queue) -> None:
        with self._sse_lock:
            try:
                self._sse_clients.remove(q)
            except ValueError:
                pass

    def broadcast_event(self, event_type: str, data: dict) -> None:
        """Broadcast an SSE event to all connected clients."""
        msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
        with self._sse_lock:
            dead = []
            for q in self._sse_clients:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._sse_clients.remove(q)



# ── Request handler ────────────────────────────────────────────────────────────

class GridSecAPIHandler(BaseHTTPRequestHandler):

    @property
    def _state(self):
        return self.server.state

    def setup(self):
        super().setup()
        self.connection.settimeout(5.0)

    def log_message(self, format, *args):
        # Suppress default access log (too noisy); use our logger instead
        logger.debug(f"REST: {self.address_string()} {format % args}")

    # ── Auth ────────────────────────────────────────────────────────────────

    def _is_authorized(self) -> bool:
        if not self._state.auth_enabled:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return secrets.compare_digest(auth[7:], self._state.api_key)
        return False

    # ── Response helpers ─────────────────────────────────────────────────────

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, content_type: str = "text/plain",
                   status: int = 200, filename: str = "") -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: str, content_type: str, filename: str = "") -> None:
        if not os.path.isfile(path):
            self._send_json({"error": "File not found"}, 404)
            return
        size = os.path.getsize(path)
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        with open(path, "rb") as f:
            remaining = size
            while remaining and (chunk := f.read(min(8192, remaining))):
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def _unauthorized(self) -> None:
        self._send_json({
            "error": "Unauthorized",
            "hint":  "Include: Authorization: Bearer <api_key>"
        }, 401)

    # ── Route dispatcher ────────────────────────────────────────────────────

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"
        params = dict(urllib.parse.parse_qsl(parsed.query))

        # Auth check (except for /api/v1/status which is public)
        if path not in ("/", "/api/v1/docs", "/api/v1/status") and not self._is_authorized():
            self._unauthorized()
            return

        routes = {
            "/api/v1/status":           self._handle_status,
            "/api/v1/simulation":       self._handle_simulation,
            "/api/v1/topology":         self._handle_topology,
            "/api/v1/attacks/current":  self._handle_attacks,
            "/api/v1/incidents":        lambda: self._handle_incidents(params),
            "/api/v1/packets/recent":   lambda: self._handle_packets(params),
            "/api/v1/export/stix":      self._handle_export_stix,
            "/api/v1/export/csv":       self._handle_export_csv,
            "/api/v1/export/pcap":      self._handle_export_pcap,
            "/api/v1/events":           self._handle_sse,
            "/api/v1/docs":             self._handle_docs,
            "/":                        self._handle_docs,
        }

        handler = routes.get(path)
        if handler:
            try:
                handler()
            except (ValueError, TypeError) as exc:
                self._send_json({"error": str(exc)}, 400)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass
            except Exception as exc:
                logger.error(f"REST handler error: {exc}")
                self._send_json({"error": "Internal server error"}, 500)
        else:
            self._send_json({"error": f"Not found: {path}"}, 404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path.rstrip("/")

        if not self._is_authorized():
            self._unauthorized()
            return

        try:
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Chunked request bodies are not supported")
            content_len = int(self.headers.get("Content-Length", 0))
            if not 0 <= content_len <= 65536:
                raise ValueError("Content-Length must be between 0 and 65536")
            body_raw = self.rfile.read(content_len) if content_len else b"{}"
            body = json.loads(body_raw)
            if not isinstance(body, dict):
                raise ValueError("Request body must be a JSON object")
            if path == "/api/v1/attack/enable":
                self._handle_attack_enable(body)
            elif path == "/api/v1/attack/disable":
                self._handle_attack_disable()
            else:
                self._send_json({"error": f"Not found: {path}"}, 404)
        except (ValueError, TypeError, UnicodeError) as exc:
            self._send_json({"error": str(exc)}, 400)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception:
            logger.exception("REST attack callback failed")
            self._send_json({"error": "Attack operation failed"}, 500)

    # ── Handlers ────────────────────────────────────────────────────────────

    def _handle_status(self) -> None:
        status = {}
        if self._state.get_status:
            status = self._state.get_status()
        self._send_json({
            "tool":      "GridSec Sim",
            "version":   "1.0.0",
            "timestamp": time.time(),
            "auth":      self._state.auth_enabled,
            **status,
        })

    def _handle_simulation(self) -> None:
        data = self._state.get_status() if self._state.get_status else {}
        self._send_json(data)

    def _handle_topology(self) -> None:
        data = self._state.get_topology() if self._state.get_topology else {}
        self._send_json(data)

    def _handle_attacks(self) -> None:
        data = self._state.get_attacks() if self._state.get_attacks else {}
        self._send_json(data)

    def _handle_incidents(self, params: dict) -> None:
        incidents = self._state.get_incidents() if self._state.get_incidents else []
        limit = self._limit(params, 100)
        proto = params.get("proto", "").upper()
        if proto:
            incidents = [i for i in incidents if i.get("protocol", "").upper() == proto]
        self._send_json({
            "count":     len(incidents[-limit:]),
            "total":     len(incidents),
            "incidents": incidents[-limit:],
        })

    def _handle_packets(self, params: dict) -> None:
        packets = self._state.get_packets() if self._state.get_packets else []
        limit = self._limit(params, 50)
        self._send_json({
            "count":   len(packets[-limit:]),
            "packets": packets[-limit:],
        })

    @staticmethod
    def _limit(params, default):
        limit = int(params.get("limit", default))
        if not 1 <= limit <= 10000:
            raise ValueError("limit must be between 1 and 10000")
        return limit

    def _handle_export_stix(self) -> None:
        bundle = self._state.get_stix() if self._state.get_stix else {}
        self._send_text(
            json.dumps(bundle, indent=2),
            content_type="application/json",
            filename="gridsec_stix2.json",
        )

    def _handle_export_csv(self) -> None:
        csv_data = self._state.get_csv() if self._state.get_csv else ""
        self._send_text(csv_data, content_type="text/csv",
                        filename="gridsec_incidents.csv")

    def _handle_export_pcap(self) -> None:
        if not self._state.get_pcap_path:
            self._send_json({"error": "pcap capture not active"}, 404)
            return
        path = self._state.get_pcap_path()
        if not path or not os.path.isfile(path):
            self._send_json({"error": "pcap file not available"}, 404)
            return
        self._send_file(path, "application/vnd.tcpdump.pcap",
                        filename="gridsec_capture.pcap")

    def _handle_attack_enable(self, body: dict) -> None:
        attack_type = body.get("type", "")
        params      = body.get("params", {})
        if not isinstance(attack_type, str) or not attack_type:
            self._send_json({"error": "Missing 'type' field"}, 400)
            return
        if not isinstance(params, dict):
            raise ValueError("params must be a JSON object")
        success = False
        if self._state.enable_attack:
            success = self._state.enable_attack(attack_type, params)
        self._send_json({"success": bool(success), "attack_type": attack_type},
                        200 if success else 503)

    def _handle_attack_disable(self) -> None:
        success = self._state.disable_attack() if self._state.disable_attack else False
        self._send_json({"success": bool(success)},
                        200 if success else 503)

    def _handle_sse(self) -> None:
        """Server-Sent Events: push live packet events to connected clients."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        q = self._state.add_sse_client()
        # Register before sending the initial ping so no events are missed.
        try:
            self.wfile.write(b": GridSec Sim SSE stream\n\n")
            self.wfile.flush()
        except Exception:
            self._state.remove_sse_client(q)
            return
        try:
            while not self.server.stop_event.is_set():
                try:
                    msg = q.get(timeout=0.5)
                    self.wfile.write(msg.encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    # Keepalive comment
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except Exception:
            pass
        finally:
            self._state.remove_sse_client(q)

    def _handle_docs(self) -> None:
        """Serve a simple HTML API documentation page."""
        html = _API_DOCS_HTML.format(
            host=escape(self.headers.get("Host", "127.0.0.1:8080")),
            api_key="YOUR_API_KEY" if self._state.auth_enabled else "(auth disabled)",
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html.encode())))
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))


# ── API docs HTML ─────────────────────────────────────────────────────────────

_API_DOCS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GridSec Sim REST API</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f0f1e; color: #e2e8f0;
         max-width: 900px; margin: 0 auto; padding: 2rem; }}
  h1   {{ color: #a78bfa; }} h2 {{ color: #7c3aed; margin-top: 2rem; }}
  code {{ background: #1a1a2e; padding: 2px 6px; border-radius: 4px;
          color: #34d399; font-size: 13px; }}
  pre  {{ background: #1a1a2e; padding: 1rem; border-radius: 8px;
          border-left: 3px solid #7c3aed; overflow-x: auto; }}
  .ep  {{ display: flex; align-items: center; gap: 1rem; padding: 0.5rem 0;
          border-bottom: 1px solid #2d2d44; }}
  .method-get  {{ color: #34d399; font-weight: 700; min-width: 45px; }}
  .method-post {{ color: #f59e0b; font-weight: 700; min-width: 45px; }}
  .path {{ color: #a78bfa; }}
  .desc {{ color: #94a3b8; font-size: 13px; }}
  .key-box {{ background: #1a1a2e; border: 1px solid #7c3aed; border-radius: 8px;
              padding: 1rem; margin: 1rem 0; }}
  .badge {{ background: #7c3aed; color: #fff; padding: 2px 8px;
            border-radius: 99px; font-size: 11px; }}
</style>
</head>
<body>
<h1>GridSec Sim — REST API</h1>
<p>OT Security Simulation Tool &nbsp; <span class="badge">v1.0</span></p>

<div class="key-box">
  <b>API Key:</b> <code>{api_key}</code><br>
  <small>Include in header: <code>Authorization: Bearer {api_key}</code></small>
</div>

<h2>Endpoints</h2>

<div class="ep"><span class="method-get">GET</span><span class="path">/api/v1/status</span><span class="desc">Simulation health (public)</span></div>
<div class="ep"><span class="method-get">GET</span><span class="path">/api/v1/simulation</span><span class="desc">Detailed simulation state</span></div>
<div class="ep"><span class="method-get">GET</span><span class="path">/api/v1/topology</span><span class="desc">Network topology (nodes + links)</span></div>
<div class="ep"><span class="method-get">GET</span><span class="path">/api/v1/attacks/current</span><span class="desc">Active attacks and parameters</span></div>
<div class="ep"><span class="method-get">GET</span><span class="path">/api/v1/incidents?limit=100&amp;proto=DNP3</span><span class="desc">Incident log (filterable)</span></div>
<div class="ep"><span class="method-get">GET</span><span class="path">/api/v1/packets/recent?limit=50</span><span class="desc">Recent captured packets</span></div>
<div class="ep"><span class="method-get">GET</span><span class="path">/api/v1/export/stix</span><span class="desc">Download STIX 2.1 bundle</span></div>
<div class="ep"><span class="method-get">GET</span><span class="path">/api/v1/export/csv</span><span class="desc">Download incident CSV</span></div>
<div class="ep"><span class="method-get">GET</span><span class="path">/api/v1/export/pcap</span><span class="desc">Download capture file</span></div>
<div class="ep"><span class="method-get">GET</span><span class="path">/api/v1/events</span><span class="desc">SSE live event stream</span></div>
<div class="ep"><span class="method-post">POST</span><span class="path">/api/v1/attack/enable</span><span class="desc">Enable attack remotely</span></div>
<div class="ep"><span class="method-post">POST</span><span class="path">/api/v1/attack/disable</span><span class="desc">Disable all attacks</span></div>

<h2>Example cURL</h2>
<pre>
# Status (no auth)
curl http://{host}/api/v1/status

# Incidents
curl -H "Authorization: Bearer {api_key}" \\
     http://{host}/api/v1/incidents?limit=20

# Enable noise attack remotely
curl -X POST -H "Authorization: Bearer {api_key}" \\
     -H "Content-Type: application/json" \\
     -d '{{"type":"NOISE","params":{{"std_dev":5.0}}}}' \\
     http://{host}/api/v1/attack/enable

# SSE live stream (EventSource in browser or curl --no-buffer)
curl --no-buffer -H "Authorization: Bearer {api_key}" \\
     http://{host}/api/v1/events
</pre>

<h2>Dragos / Claroty Integration</h2>
<pre>
# Poll incidents every 60 seconds from Dragos/Claroty:
curl -H "Authorization: Bearer {api_key}" \\
     "http://{host}/api/v1/incidents?limit=100" | jq .

# Download STIX 2.1 for threat intelligence import:
curl -H "Authorization: Bearer {api_key}" \\
     "http://{host}/api/v1/export/stix" -o gridsec_threats.json
</pre>
</body>
</html>
"""


# ── REST API Server ────────────────────────────────────────────────────────────

class GridSecRESTServer:
    """
    Threaded REST API server for GridSec Sim.

    Usage:
        server = GridSecRESTServer(host="0.0.0.0", port=8080)
        server.set_status_callback(lambda: {"sim_running": True})
        server.start()
        ...
        server.stop()
        print(server.api_key)   # share this with integrations
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self._state = APIState()
        self.last_error = ""
        self._host   = host
        self._port   = port
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    # ── Callback setters ────────────────────────────────────────────────────

    def set_status_callback(self, fn: Callable)   -> None: self._state.get_status    = fn
    def set_topology_callback(self, fn: Callable) -> None: self._state.get_topology  = fn
    def set_attacks_callback(self, fn: Callable)  -> None: self._state.get_attacks   = fn
    def set_incidents_callback(self, fn: Callable)-> None: self._state.get_incidents = fn
    def set_packets_callback(self, fn: Callable)  -> None: self._state.get_packets   = fn
    def set_stix_callback(self, fn: Callable)     -> None: self._state.get_stix      = fn
    def set_csv_callback(self, fn: Callable)      -> None: self._state.get_csv       = fn
    def set_pcap_path_callback(self, fn: Callable)-> None: self._state.get_pcap_path = fn
    def set_enable_attack_callback(self, fn: Callable) -> None: self._state.enable_attack  = fn
    def set_disable_attack_callback(self, fn: Callable)-> None: self._state.disable_attack = fn

    def set_api_key(self, key: str)      -> None: self._state.api_key      = key
    def disable_auth(self)               -> None: self._state.auth_enabled  = False
    def enable_auth(self)                -> None: self._state.auth_enabled  = True

    @property
    def api_key(self) -> str:
        return self._state.api_key

    @property
    def port(self) -> int:
        return self._port

    def broadcast_event(self, event_type: str, data: dict) -> None:
        """Push a live event to all SSE subscribers."""
        self._state.broadcast_event(event_type, data)

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Start the REST API server in a daemon thread. Returns True on success."""
        if self._running:
            return True
        try:
            self._state.stop_event = threading.Event()
            self._server = ThreadingHTTPServer((self._host, self._port), GridSecAPIHandler)
            self._server.daemon_threads = True
            self._server.state = self._state
            self._server.stop_event = self._state.stop_event
            self._port = self._server.server_port
            self._running = True
            self._thread  = threading.Thread(
                target=self._server.serve_forever, kwargs={"poll_interval": 0.1},
                daemon=True, name="REST-API"
            )
            self._thread.start()
            logger.info(f"REST API: http://{self._host}:{self._port}/api/v1/status")
            self.last_error = ""
            return True
        except OSError as e:
            self.last_error = str(e)
            self._running = False
            logger.error(f"REST API failed to start on port {self._port}: {e}")
            return False

    def stop(self) -> None:
        self._running = False
        self._state.stop_event.set()
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
        self._thread = None
        logger.info("REST API server stopped")

    def _serve(self) -> None:
        try:
            self._server.serve_forever()
        except Exception as exc:
            if self._running:
                logger.error(f"REST API server error: {exc}")
