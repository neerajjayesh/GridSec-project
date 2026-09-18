# Integrations and exports

[Documentation index](index.md)

## Integration status

| Path | Current status |
|---|---|
| Main proxy → UDP PDC destination | Desktop-wired; external receiver setup and interoperability remain your responsibility |
| Incident JSON/CSV | Desktop export methods exist and receive proxy records |
| STIX | Exporter exists; experimental representation and taxonomy mappings |
| PCAP writer | Core implementation; GUI start/stop methods and raw-byte delivery are incomplete |
| Syslog/CEF | Core sender; GUI convenience-method wiring is incomplete |
| REST | Core server; GUI convenience methods and remote engine hooks are incomplete |
| Named vendor integrations | Generic format/interface possibilities, not tested product connectors |

## Connect a PDC receiver

The desktop sends UDP. Configure your laboratory receiver for the same transport and the generated C37.118 layout: ID 1, three float polar phasors, one float analog, one digital word, 50 Hz nominal, 30 frames/s. Match the receiver to the generator's CFG-2 and data layout rather than assuming every receiver can infer it automatically.

1. Start the receiver on a chosen lab address/UDP port.
2. Stop GridSec simulation, select the first **Local PDC**, and set its IP/port to that receiver.
3. Keep the first PMU's listen port distinct from the receiver port when both use loopback.
4. Validate and start a clean baseline.
5. Confirm incoming datagrams and accepted measurements at the receiver.
6. Apply a controlled transformation and verify the receiver's values, timestamps, and invalid-frame indicators.

openPDC is an intended receiver use case, but this review did not test an openPDC installation. A TCP-only receiver will not receive the GUI's UDP stream. The core TCP proxy does not turn the UDP generator into a complete command-driven PMU.

CFG-2 is sent once at PMU startup. If the receiver missed it, start the receiver first and restart the experiment. For modified data, account for the current parser digital-word mismatch described in [Protocols](protocols.md).

## PCAP and Wireshark

`PcapWriter` creates classic Ethernet-linktype PCAP files with microsecond timestamps. UDP/TCP methods synthesize Ethernet/IP/transport headers around supplied application bytes. GOOSE accepts a supplied raw Ethernet frame. This is generated capture material, not a passive copy of actual NIC traffic or a complete TCP handshake.

Regular-file mode opens the destination with `wb`, replacing existing content. FIFO mode is POSIX-only, replaces an existing path with a named pipe, and waits for a reader in a background thread. Use a new dedicated output path. Check `is_active` and `error`; construction/start messages do not guarantee successful capture.

Current desktop limitations are two independent issues:

1. Capture buttons call `start_pcap_only()`/`stop_pcap_only()`, absent from `IntegrationManager`.
2. The main window retrieves `record.raw_bytes`, but `PacketRecord.__slots__` has no such field. The resulting empty bytes skip PCAP writes and appear as packet length zero.

The [offline frame example](examples/inspect_frame.py) can create a real sample PCAP through the core writer:

```powershell
.\.venv\Scripts\python.exe docs/examples/inspect_frame.py --pcap sample-frame.pcap
```

Open the file in Wireshark. Its addresses are synthetic documentation values. For a genuine live-network trace, capture the relevant loopback/lab interface independently and compare it with the application records. The GUI's Wireshark launcher can find a native executable or attempt WSL on Windows, but a successful launcher does not fix capture wiring.

## Syslog/CEF

The core sender formats a CEF message inside an RFC-5424-style syslog envelope. UDP is default; TCP sends newline-terminated messages. Default destination is `127.0.0.1:514`, facility LOCAL7.

When configured and started programmatically, the manager sends attacked, dropped, and invalid records; it does not send clean records. Severity is derived from status: clean INFO, attacked HIGH, dropped MEDIUM, invalid LOW. CEF numeric levels are 0, 7, 5, and 3 respectively.

For an authorized collector integration, use `configure_syslog()` and `start()` on the core manager, then call `record_packet()` as records arrive. Check collector receipt independently: UDP socket creation and `sendto()` success do not acknowledge ingestion. The sender provides no TLS, durable buffering, retry queue, or complete escaping of arbitrary user-controlled CEF fields.

The GUI's Syslog Test/Enable/Disable buttons call missing manager convenience methods. `patch_mgr.py` is an old source-rewriting helper, not a supported installation or runtime step.

## JSON and CSV

JSON export includes session ID, export time, and retained incidents with original/modified fields. CSV contains nine event-summary columns. Both include clean records because the manager creates an Incident for every callback record, not only attacks.

Export before memory rotation or application exit. With roughly 30 records/s, 10,000 incident entries represent about 5.6 minutes, depending on configuration records and actual processing. These are retained records, not a durable experiment archive.

## STIX

The exporter labels output as STIX 2.1 and builds identity, campaign, attack-pattern, indicator, course-of-action, relationship, and observed-data objects. Observed-data samples only the last 20 attacked incidents; it does not reproduce the full history.

The output uses custom ICS fields and static ATT&CK mappings. It has not been validated against a strict STIX validator or an external platform during this review. Broad port indicators do not independently identify an attack, and repository technique mappings require review before use as authoritative classifications. Retain JSON/CSV as the primary experiment record.

## Core lifecycle example

```python
from core.integration_manager import IntegrationManager

manager = IntegrationManager()
manager.configure_rest_api(host="127.0.0.1", port=18080)
results = manager.start()
try:
    # Your application supplies records through manager.record_packet(...).
    # Keep this process alive while clients use the server.
    print(results)
finally:
    manager.stop()
```

This fragment demonstrates lifecycle only; it exits immediately without a host event loop. Use [serve_api.py](examples/serve_api.py) for a runnable version. Start configured integrations once, inspect results, and stop them explicitly. Disconnect SSE clients before shutdown.

Source: [manager/exporters](../core/integration_manager.py), [PCAP writer](../core/pcap_writer.py), [integration panel](../gui/integration_panel.py), [proxy](../core/pdc_proxy.py).
