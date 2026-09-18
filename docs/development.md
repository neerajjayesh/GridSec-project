# Developer guide

[Documentation index](index.md) · [Contributing](../CONTRIBUTING.md)

## Development environment

Create a dedicated environment using [Getting started](getting-started.md), install `requirements.txt`, then run `test_regression.py`. The project is a source-tree application rather than an installed package: `main.py` inserts its directory into `sys.path`. There is no `pyproject.toml`, package build configuration, linter configuration, or dependency lockfile.

Run module self-checks with `python -m protocols.c37118` and similar module forms from the root to preserve import resolution. Existing shell deployment/test helpers contain fixed workstation paths; inspect them instead of assuming portability.

## Source map

| Files | Responsibility |
|---|---|
| `main.py` | Application bootstrap and process-level logging/error handling |
| `core/pmu_simulator.py`, `core/pdc_proxy.py` | Primary UDP producer and forwarding pipeline; optional core TCP proxy |
| `core/attack_engine.py`, `core/traffic_filter.py` | Transformation contract, scheduling, and packet eligibility |
| `core/packet_parser.py` | Protocol wrapper and global codec |
| `core/*_simulator.py` | Auxiliary GOOSE, DNP3, and Modbus traffic |
| `core/integration_manager.py` | Incident model, exports, Syslog/CEF, integration lifecycle |
| `core/rest_api.py`, `core/pcap_writer.py` | HTTP interface and synthesized capture writing |
| `protocols/` | Protocol-specific encoding/decoding helpers |
| `gui/main_window.py` | Component wiring, menus, scenarios, runtime lifecycle |
| `gui/canvas.py`, `gui/node_types.py` | Diagram interaction, persistence, node/link graphics |
| `gui/properties_panel.py`, `gui/attack_panel.py` | Property and attack forms |
| `gui/integration_panel.py` | Capture, syslog, REST, export and integration help tabs |
| `gui/waveform_viewer.py`, `gui/styles.qss` | Matplotlib plots and Qt theme |

## Core usage

Use `AttackEngine.set_attack()` with an `AttackType` enum and documented parameter dictionary. Use `set_schedule()` separately from attack parameters. Keep codec channel counts aligned across generation, parse, and rebuild; explicitly set the parser codec for the current single-process implementation.

The [offline example](examples/inspect_frame.py) demonstrates that contract with a known digital-word sentinel and validates the rebuilt result. The [API example](examples/serve_api.py) demonstrates manager lifecycle and a synthetic record without starting auxiliary network services.

`PacketRecord` does not hold outbound wire bytes. A capture integration must deliberately choose original or rebuilt bytes and pass them to `record_packet()`. Do not infer modified wire bytes from a modified dict's inherited `raw` value.

## Add an attack module

1. Add an `AttackType` value and `BaseAttack` subclass.
2. Implement `get_params()`, `set_params()`, `reset()` when stateful, and `_apply_attack()` returning `AttackResult`.
3. Register the class in `ATTACK_CLASSES`.
4. Add an explicit form/order entry in `gui/attack_panel.py` and verify parameter synchronization.
5. Add meaningful checks for the transformation, no-op/drop behavior, reset, and any scheduling interaction.
6. Update [Attacks](attacks.md), relevant API/example metadata, and the changelog. Review export classification mappings without inventing a standards claim.

Prefer copying nested measurement arrays before modification. Validate numeric inputs and state transitions explicitly. Existing setters are not a uniform validation model to copy unquestioningly.

## Add a node type

Register type/class, names, icons, colors, default ports, and level metadata in `node_types.py`. Add palette placement in `main_window.py`, configuration fields in `properties_panel.py`, and link defaults where relevant in `canvas.py`. Verify save/load with stable IDs and attachments.

A visual node does not become an executable device simply by registering it. Runtime construction, address mapping, callbacks, stop behavior, and protocol tests must be added separately if live behavior is intended.

## Add or extend a protocol

Keep codecs independent of Qt. Define the supported wire subset, frame boundaries, units, error behavior, and representative valid/invalid vectors. Add a worker lifecycle appropriate to the transport and route callbacks through the relay for UI updates.

Decide whether the protocol observes original or modified measurements and whether it participates in attack execution. Connect nonempty raw bytes deliberately if capture is required. Verify with an independent decoder/receiver before claiming interoperability.

## Extend integrations/API

Use manager `configure_*()`, `start()`, and `stop()` as the existing core lifecycle. Add missing GUI wrappers as ordinary source changes with targeted validation; `patch_mgr.py` rewrites source and is not a supported migration.

API callbacks execute outside the Qt thread. Marshal UI mutations through signals, validate request bodies, and return actual success. Before adding concurrent clients/streams, address process-global API and codec state, serial SSE handling, shared engine mutation, and shutdown ownership.

## Engineering decisions for future scaling

The current diagram/runtime separation simplifies teaching but limits simulation fidelity. A multi-stream design should explicitly map node/link IDs to independent runtime contexts containing codec, filter, attack state, sockets, and capture policy. It should also define whether incident IDs, counters, and schedules are per stream or per session.

Keep those boundaries explicit before adding more UI switches. Confirm lifecycle ownership and failure reporting before claiming larger-scale support.

## Documentation maintenance

When behavior changes, update the relevant guide/reference, machine-readable schemas/examples, limitations, and verification notes together. Re-run the relevant checks after code changes and record the resulting behavior. Do not claim test coverage from unchecked script banners.

Source: [engine](../core/attack_engine.py), [nodes](../gui/node_types.py), [canvas](../gui/canvas.py), [manager](../core/integration_manager.py), [regression](../test_regression.py).
