# Testing and verification

[Documentation index](index.md)

## Verification baseline

The following results were recorded during documentation verification using **Windows and Python 3.14.6**. They describe the checked application checkout, rather than an automatic guarantee for later code changes. Application source was not modified during that verification.

Installed GUI/numerical package versions in that environment were PyQt6 **6.11.0**, numpy **2.5.1**, and matplotlib **3.11.0**. These are observed test versions, not a new dependency lock or a recommendation to require those exact releases.

| Check | Observed result | What it establishes |
|---|---|---|
| Existing `test_regression.py` | **201/201 passed, 0 failed** | Registered nodes/levels, canvas/property operations, ten attacks, schedule window, topology save/load and MitM attachment tests |
| C37.118 module self-check | Exit 0 | Internal codec examples/assertions, including CRC and frame round-trips |
| DNP3 module self-check | Exit 0 | Existing DNP3 framing/helper examples/assertions |
| Modbus module self-check | Exit 0 | Existing Modbus frame/register examples/assertions |
| GOOSE module self-check | Exit 0 | Offline GOOSE frame examples/assertions; no live Ethernet test |
| Attack engine self-check | Exit 0 | Existing examples for all ten modules |
| Traffic filter self-check | Exit 0 | Existing rule matching examples/assertions |
| Packet parser self-check | Exit 0 | Existing parsing/rebuilding example |
| Offscreen MainWindow construction | Passed | Window can initialize; no live simulation was started by this check |
| Documentation topology in MainWindow | Passed | Three nodes load, validation has no errors/warnings, one intercepted link survives a save/load round-trip |
| Offline frame documentation example | Passed | 56-byte original/rebuilt frame, Va 120→240 V, valid decode, unchanged frequency/timestamp/digital sentinel |
| Optional PCAP example | Passed | Two complete synthesized UDP records in a 252-byte PCAP |
| Local API example | Passed | Loopback startup, public status, auth, reads/exports, documented no-hook responses, bounded shutdown |

The API check also reproduced the documented empty `proto` filter result, root 404, unavailable PCAP 404, and missing attack type 400. It did not open an SSE stream, invoke external collectors, or enable a remote attack.

These are observed checks, not a claim that every implementation path is correct. A number of gaps remain outside existing regression coverage, as listed in [Known limitations](known-limitations.md).

## Run the existing regression suite

Windows:

```powershell
.\.venv\Scripts\python.exe test_regression.py
```

Linux/WSL:

```bash
.venv/bin/python test_regression.py
```

The script creates an offscreen Qt application and returns nonzero if a `check()` fails. It is a standalone script, not a pytest suite. Some attack checks involve randomness and timing tolerances. Preserve failure output and investigate before repeating a failed run; repeated success alone does not explain a failure.

## Run protocol/core self-checks

After activating your project environment, run from the repository root:

```bash
python -X utf8 -m protocols.c37118
python -X utf8 -m protocols.dnp3
python -X utf8 -m protocols.modbus
python -X utf8 -m protocols.goose
python -X utf8 -m core.attack_engine
python -X utf8 -m core.traffic_filter
python -X utf8 -m core.packet_parser
```

You can substitute the environment's full interpreter path for `python`. `-X utf8` avoids Windows console-encoding failures caused by Unicode success symbols. The first verification wrapper encountered such an output-encoding error; repeating the module checks with UTF-8 produced the results above. That was a reporting-environment issue, not a codec assertion failure.

These self-checks cover their embedded examples only. Printing “ALL TESTS PASSED” is not an external standards validation or a comprehensive test inventory.

## Run documentation examples

```bash
python docs/examples/inspect_frame.py
python docs/examples/inspect_frame.py --pcap sample-frame.pcap
python docs/examples/serve_api.py --port 18080 --duration 10
```

The PCAP example requires a new filename and opens no network sockets. The API example opens one loopback HTTP listener, prints a local token, and serves one synthetic incident. Use another terminal to query it while running. Omit `--duration` for an interactive session terminated with `Ctrl+C`.

## Manual smoke checks for functional changes

| Change area | Useful validation |
|---|---|
| Topology/editor | Add/edit/remove nodes, validate, save/reload, inspect stable IDs and attachment restoration |
| Attack behavior | Verify exact transformed values, no-op/drop flags, boundaries, schedule indexing and reset behavior |
| Codec/parser | Check encoded length, CRC, channel counts, timestamp preservation, malformed/short input, and independent decoder acceptance |
| GUI runtime | Start/stop on isolated endpoints; inspect actual worker/socket state and receiver receipt |
| Capture | Confirm nonempty selected wire bytes, packet count, headers and independent PCAP parsing |
| API | Check auth, bad payloads, hook outcomes, actual state transitions, client concurrency and shutdown |
| Integration lifecycle | Check bind/open failure, stop/restart, resource cleanup and missing GUI wiring |

A manual GUI run should start with Clean Baseline, then a controlled magnitude/frequency change, then a reset and finite schedule. For packet loss/delay, use receiver-side timing/counts rather than expecting the waveform alone to show delivery behavior.

## Historical shell scripts

| File | Current caveat |
|---|---|
| `test_all.sh` | Assumes `~/GridSecSim` and `venv/`; limited module checks |
| `test_launch.sh` | Copies files from a fixed workstation path before launching a check |
| `deploy_and_test.sh`, `deploy_integration.sh` | Copy/overwrite files between fixed Windows/WSL locations |
| `patch_mgr.py` | Rewrites manager source; not a test or supported migration |

Use the direct Python commands above for portable verification. Do not run source-copying scripts just to obtain a test result.

## Documentation artifact checks

The documentation review checks local Markdown targets, JSON syntax/internal references, Python example syntax, API route coverage against the handler, and example topology references. The topology example is also loaded through the actual canvas.

The JSON Schema and OpenAPI files are reference artifacts, not newly installed validators or API behavior changes. Full third-party schema/OpenAPI conformance validation is not claimed. Likewise, STIX export has not been checked with a strict external validator.

## Not verified in this review

- Live openPDC or another external PDC receiving modified frames.
- Live Linux/WSL raw Ethernet GOOSE publishing.
- External SIEM/syslog collector receipt or named vendor interoperability.
- Full standards conformance, long-duration stability, measured capacity, or concurrent API/SSE load.
- Linux/WSL installation from a clean machine, GUI visual behavior across display stacks, or a packaged release.

Source: [regression suite](../test_regression.py), [codec self-checks](../protocols/c37118.py), [engine self-check](../core/attack_engine.py), [documentation examples](examples/inspect_frame.py).
