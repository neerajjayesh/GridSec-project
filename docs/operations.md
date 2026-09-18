# Operations and troubleshooting

[Documentation index](index.md)

## Deployment profile

Run as a desktop laboratory application from a known checkout and dedicated Python environment. Keep experiment files in a writable output directory and preserve source revision/package versions with results. No service installer, container, database migration, automatic updater, or production deployment procedure is supplied.

Starting Run attempts auxiliary services even for a small C37.118-only diagram. Use an isolated lab environment whose network interfaces and receiver endpoints you understand. Basic C37.118 experiments can run without raw-socket privileges.

## Network footprint

| Component | Default desktop behavior |
|---|---|
| PMU | UDP from an ephemeral source port to loopback/first PMU port, normally 4712 |
| C37.118 proxy | Binds `127.0.0.1:4712`; forwards to first Local PDC, normally `127.0.0.1:4713` |
| Local PDC node | No listener created; represents an external destination |
| DNP3 | UDP bind `0.0.0.0:20000`, fallback ephemeral bind; target loopback port 20000 |
| Modbus | TCP server loopback port 502, fallback 10502; local polling master |
| GOOSE | Attempts raw Ethernet publishing on autodetected Linux interface |
| REST | Not automatically started by Run; core default loopback:8080, manager configuration default all interfaces:8080 |
| Syslog | Sends to configured collector only when configured/started; default loopback:514 |

Link labels and node ports for IEDs, switches, or State PDC do not imply additional listeners. Avoid using the same local endpoint for proxy input and forwarding output, which can cause a feedback loop.

## Run procedure

1. Save current topology and record experiment settings.
2. Verify the selected input/output ports are free or belong to your intended receiver.
3. Start the receiver first if delivery validation matters.
4. Load/validate the topology while stopped.
5. Reset attack statistics and module state; review schedule and parameters.
6. Start a clean baseline and confirm proxy activity and receiver receipt.
7. Apply the intended change; collect application and receiver evidence.
8. Stop, export retained records, and save the final topology/settings.
9. Shut down any separately started API/capture/collector resources explicitly.

There is no autosave or automatic incident recovery. A topology is not a complete session backup. Keep JSON incident exports for detailed values; CSV is a summary and STIX is sampled.

## Capacity and retention

| Resource | Bound/default |
|---|---|
| Desktop C37.118 streams | 1 |
| PMU rate | 30 data frames/s from GUI; constructor accepts 1–120 |
| Active attack modules | 1 |
| Waveform buffer | 120 samples per channel |
| Plot refresh | 10 Hz for active plot |
| GUI log target | 500 lines, with batched trimming |
| Incidents | Last 10,000 records |
| Recent packet summaries | Last 1,000 records |
| SSE subscriber queue | 100 pending messages |

At 30 records/s, the incident window is approximately 5.6 minutes and packet-summary window approximately 33 seconds. This is arithmetic from configured bounds, not a throughput benchmark. Extra records, delay, and loss change effective durations. There is no capture rotation or disk-quota manager.

## Logs and diagnostics

`GRIDSEC_LOG_LEVEL=DEBUG` increases console logging. No rotating log file is configured. API startup logs the bearer token; redact it before sharing diagnostics.

PowerShell:

```powershell
$env:GRIDSEC_LOG_LEVEL = 'DEBUG'
.\.venv\Scripts\python.exe main.py --demo *> gridsec-session.log
Get-NetUDPEndpoint | Where-Object LocalPort -in 4712,4713,20000
Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 502,10502,8080,18080
```

Linux:

```bash
GRIDSEC_LOG_LEVEL=DEBUG .venv/bin/python main.py --demo > gridsec-session.log 2>&1
ss -lunp
ss -ltnp
```

Run socket inspection from another terminal while the application is active. These commands inspect listeners; they do not confirm application-level measurement acceptance.

## Troubleshooting

| Symptom | Likely explanation and action |
|---|---|
| `No module named PyQt6` | Wrong interpreter or incomplete install. Use the environment's Python and reinstall requirements there. |
| No visible Linux/WSL window | Missing display environment caused offscreen fallback. Confirm WSLg/display server and launch in a display-enabled session. |
| Qt XCB/plugin error | Missing/incompatible display libraries or environment. Verify distribution Qt dependencies and test offscreen separately. |
| Port already in use | Inspect the owner. Change the first PMU port or intended receiver port while stopped, then restart. |
| Packets plot but receiver sees nothing | Local PDC node is not a receiver. Check real listener, UDP/TCP match, destination, firewall/interface, and startup CFG-2 receipt. |
| Modified frames rejected downstream | Check codec channel counts and digital-word mismatch GS-08. Inspect outgoing bytes/configuration compatibility. |
| No attack effect | Confirm dropdown selection, enable toggle, schedule counter/window, and module-specific target. Reset state before a controlled repeat. |
| Replay initially looks clean | Buffer is still recording N frames; modifications begin afterward. |
| Drop does not make plot gaps | Plot consumes dropped records. Use dropped counter and receiver capture. |
| Delay looks clean | Expected classification; inspect elapsed delivery timing and throughput. |
| Capture/REST/Syslog button raises AttributeError | Missing convenience methods, GS-13. Use documented core interfaces; do not run patch helpers blindly. |
| PCAP empty or packet lengths zero | GUI lacks raw-byte delivery, GS-14; a writer alone is insufficient. |
| API protocol query empty | `proto`/`protocol` mismatch. Omit query filter and filter client-side. |
| API stops responding after SSE starts | Serial HTTP handler is occupied. Disconnect SSE and use polling. |
| API enable returns false | No attack hook installed. Desktop does not connect one. |
| API says simulation still running after Stop | Stale manager flag, GS-21. Check desktop/proxy state directly. |
| GOOSE fails on Windows | Linux socket family unavailable; use Linux lab for live Layer 2 publishing. |
| Modbus appears on 10502 | Port 502 bind failed and server used its high-port fallback. |
| Long stop/restart or slow stream | Delay sleeps on proxy worker; workers stop asynchronously. Wait for termination before reusing ports. |

## Recovery and change management

Export records before closing whenever possible. After a crash, restart from a saved topology, reapply attack parameters/schedule, and begin a fresh baseline. In-memory incidents and module buffers are not recoverable.

For an update, preserve topology/export files and environment version records, stop the app, update the source in a controlled checkout, install requirements into a fresh environment, and run regression plus a relevant smoke check. To roll back, use the previous checkout/environment and revalidate the topology. Do not use workstation-specific deployment scripts as a release system.

Source: [entry](../main.py), [runtime](../gui/main_window.py), [manager bounds](../core/integration_manager.py), [DNP3](../core/dnp3_simulator.py), [Modbus](../core/modbus_simulator.py).
