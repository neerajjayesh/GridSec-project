import re

with open(r'core/integration_manager.py', 'r', encoding='utf-8') as f:
    content = f.read()

extra = r'''
    # ── GUI convenience methods (called by integration_panel.py) ─────────────

    def start_pcap_only(self) -> dict:
        if self._pcap:
            self._pcap.close()
            self._pcap = None
        if not self._pcap_cfg:
            return {"pcap": "error: not configured"}
        try:
            self._pcap = PcapWriter(
                path     = self._pcap_cfg.get("path", "/tmp/gridsec_capture.pcap"),
                use_fifo = self._pcap_cfg.get("use_fifo", False),
            )
            return {"pcap": "started"}
        except Exception as e:
            return {"pcap": f"error: {e}"}

    def stop_pcap_only(self) -> None:
        if self._pcap:
            self._pcap.close()
            self._pcap = None

    def start_syslog_only(self) -> str:
        if self._syslog:
            self._syslog.disconnect()
            self._syslog = None
        if not self._syslog_cfg:
            return "error: not configured"
        try:
            self._syslog = SyslogCEFSender(**self._syslog_cfg)
            ok = self._syslog.connect()
            return "connected" if ok else f"error: {self._syslog.last_error}"
        except Exception as e:
            return f"error: {e}"

    def stop_syslog_only(self) -> None:
        if self._syslog:
            self._syslog.disconnect()
            self._syslog = None

    def test_syslog(self) -> tuple:
        if not self._syslog_cfg:
            return False, "Syslog not configured"
        sender = SyslogCEFSender(**self._syslog_cfg)
        return sender.test_connection()

    def start_rest_only(self) -> str:
        if self._rest:
            self._rest.stop()
            self._rest = None
        if not self._rest_cfg:
            return "error: not configured"
        try:
            self._rest = GridSecRESTServer(**self._rest_cfg)
            self._wire_rest_callbacks()
            ok = self._rest.start()
            return f"listening on port {self._rest.port}" if ok else "failed to start"
        except Exception as e:
            return f"error: {e}"

    def stop_rest_only(self) -> None:
        if self._rest:
            self._rest.stop()
            self._rest = None

    def disable_rest_auth(self) -> None:
        if self._rest:
            self._rest.disable_auth()

'''

marker = '# ── Helpers ─'
idx = content.find(marker)
if idx == -1:
    print("ERROR: marker not found")
else:
    content = content[:idx] + extra + content[idx:]
    with open(r'core/integration_manager.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Done. Total lines: {len(content.splitlines())}")
