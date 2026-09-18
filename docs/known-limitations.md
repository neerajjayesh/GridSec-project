# Known limitations

[Documentation index](index.md)

These findings describe the documented application implementation. They are implementation constraints, not speculative vulnerabilities or a list of completed fixes.

## Runtime and topology

| ID | Finding | Practical consequence |
|---|---|---|
| GS-01 | Desktop creates one PMU/proxy from the first PMU and Local PDC. | Multiple nodes/links do not create simultaneous independent flows. |
| GS-02 | Runtime fixes loopback PMU input, UDP, 30 frames/s, 50 Hz, 120 V, and PMU ID 1. | PMU IP, reporting rate, ID and node transport edits do not control those settings. |
| GS-03 | Threat Agent attachments/scope are not consulted by the runtime engine. | Attacks can run without an attached agent; selected-link scope is not enforcement. |
| GS-04 | Saved agent attack metadata is not loaded into the engine. | Loading a topology does not arm its saved attack policy. |
| GS-05 | Engine counters/state/schedule survive Stop/Run. | Reset explicitly for comparable runs; a finite window may already be over. |
| GS-06 | Ordinary Open can replace a running diagram; scenario selection can still alter attacks when demo loading is blocked. | Stop before loading diagrams or scenarios. |
| GS-07 | Top-level Attacks menu ignores its selected module argument. | Use the Attacks-tab dropdown and enable action. |

Sources: [MainWindow](../gui/main_window.py), [AttackPanel](../gui/attack_panel.py), [Canvas](../gui/canvas.py).

## Packet integrity and observation

| ID | Finding | Practical consequence |
|---|---|---|
| GS-08 | Parser global codec has zero digital words; PMU generates one; proxy does not call `set_codec()`. | Modified frames can omit the digital word and no longer match initial CFG-2 layout. |
| GS-09 | Rebuild exceptions fall back to original raw bytes; modified classification remains. | An attacked record alone does not prove changed outgoing bytes. |
| GS-10 | Records precede forwarding and plots accept dropped/non-data records. | Plots and dashboard do not verify receiver delivery; startup artifacts and loss without gaps are possible. |
| GS-11 | Delay returns no content-modified/drop flag. | Delayed packets appear clean and do not create attacked SSE/syslog events. |
| GS-12 | Auxiliary protocols use original measurements and independent singleton simulators. | C37.118 attack effects do not propagate to GOOSE/DNP3/Modbus. |

Sources: [Parser](../core/packet_parser.py), [Proxy](../core/pdc_proxy.py), [Engine](../core/attack_engine.py), [Viewer](../gui/waveform_viewer.py).

## Integration and API

| ID | Finding | Practical consequence |
|---|---|---|
| GS-13 | Manager lacks panel-used convenience methods: `start_pcap_only`, `stop_pcap_only`, `start_syslog_only`, `stop_syslog_only`, `test_syslog`, `start_rest_only`, `stop_rest_only`, `disable_rest_auth`. | Affected integration buttons can raise AttributeError. Core configure/start/stop interfaces remain available. |
| GS-14 | GUI reads missing `PacketRecord.raw_bytes`. | PCAP receives empty payloads; recent packet lengths are zero. Fixing only Start Capture does not fix capture data. |
| GS-15 | Desktop records synthetic addresses/ports and only C37.118 callbacks. | Exports do not faithfully represent live endpoint addresses or all auxiliary traffic. |
| GS-16 | Desktop does not set remote attack hooks. | Enable can return false; disable can report success without changing the engine. |
| GS-17 | API `proto` filtering reads `proto` while incidents contain `protocol`. | Standard-manager filtered incident queries return empty results. |
| GS-18 | REST uses serial HTTPServer with long-lived SSE. | SSE can block other requests and delay server shutdown. |
| GS-19 | Root URL is stripped to an empty path. | Use `/api/v1/docs`; `/` is not a working help route. |
| GS-20 | API state/auth are process-global; limits and POST payloads lack consistent validation. | Independent server instances are not isolated; clients can receive 500s or broken connections for bad input. |
| GS-21 | Manager `sim_running` is not reset by desktop Stop; attack snapshot is counters only. | API status can be stale and `/attacks/current` is not a complete active-policy description. |
| GS-22 | No explicit integration-manager stop in MainWindow close; PCAP open failures may be stored without raising. | Explicit lifecycle and readiness checks are needed in embedded integrations. |
| GS-23 | STIX uses custom fields, static mappings, and limited samples. | Validate/adapt before importing; do not treat it as a conformance-certified or complete evidence package. |

Sources: [IntegrationPanel](../gui/integration_panel.py), [IntegrationManager](../core/integration_manager.py), [REST server](../core/rest_api.py), [PCAP writer](../core/pcap_writer.py).

## Platform and project maturity

- GOOSE uses Linux `AF_PACKET`; native Windows live publishing is unavailable and its worker may raise an unsupported-family exception.
- GUI startup's “running” messages do not replace socket readiness checks; startup uses fixed sleeps and several workers initialize asynchronously.
- No multi-platform live-network interoperability suite, protocol certification, production benchmark, load test, or packaged installer is established here.
- Existing `test_launch.sh` and deployment scripts contain workstation-specific paths and copy/overwrite source. They are not portable test/release commands.
- No dependency lockfile, CI workflow, durable incident store, TLS, account/role system, or authoritative `LICENSE` file is included.

See [Testing](testing.md) for what has actually been verified. A future fix should update this page, affected workflow documentation, and the corresponding validation evidence together.
