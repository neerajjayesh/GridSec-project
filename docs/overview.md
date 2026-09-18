# Product overview

[Documentation index](index.md)

**Project GitHub:** [neerajjayesh/GridSec-project](https://github.com/neerajjayesh/GridSec-project)

## Purpose and users

GridSec Sim is a visual laboratory for studying how changes to measurement traffic affect data visible to a downstream receiver. Operators create a substation diagram, start a synthetic PMU, select a stream modification, and inspect resulting measurements and packet classifications.

| User | Typical work |
|---|---|
| Instructor or student | Demonstrate clean traffic, false measurements, stale data, delay, and loss |
| Security researcher | Inspect controlled protocol changes and collect synthetic experiment records |
| Integration developer | Exercise a laboratory receiver or prototype an export consumer |
| Contributor | Extend codecs, improve runtime wiring, and maintain the desktop application |

The project focuses on measurement communication. It does not solve electrical power flow, model a physical grid, or implement a complete substation control system. A frequency override changes the reported field; it does not change a physical generator model.

## Functional scope

| Area | Current implementation |
|---|---|
| Desktop | PyQt6 canvas, property editor, attack panel, plots, packet log, and integration tabs |
| Topologies | Thirteen node types, four levels, protocol links, Threat Agent attachments, JSON persistence |
| Validation | Missing PMU/Local PDC errors; warnings for missing C37.118 links, unattached agents, and duplicate PMU ports |
| Main runtime | One UDP PMU and proxy, using the first PMU and Local PDC |
| Attacks | Ten selectable modules; one active module at a time; optional frame window |
| Visualization | Original/modified phase-A magnitude, frequency, and phase-A angle |
| Auxiliary traffic | DNP3/UDP, Modbus/TCP, and a GOOSE raw Ethernet publisher attempt |
| IEC104 | Frame helpers and diagram labels; no desktop live simulator |
| Records | In-memory incidents, recent packet metadata, JSON/CSV, experimental STIX |
| External tooling | Core PCAP, Syslog/CEF, and REST components with desktop wiring gaps |

## Experiment outcomes

A false-data experiment establishes a clean baseline, selects a known transformation, observes the modified proxy record, and verifies receipt independently when downstream delivery matters. For example, `SCALE` with `scale_factor=2.0` changes a reported 120 V magnitude to 240 V.

The plot observes proxy processing. It does not prove that a remote PDC received, accepted, or acted on the outgoing frame. Loss and latency need receiver-side or network evidence in addition to plots.

## Deployment and quality characteristics

| Characteristic | Current position |
|---|---|
| Execution | One local Python process, worker threads, Qt event loop |
| Storage | Topology/export files and bounded memory; no database |
| Distribution | Source checkout and Python requirements; no packaged executable |
| Reproducibility | Minimum dependency versions; no lockfile or GUI seed setting |
| Capacity | One desktop C37.118 stream; no measured production throughput envelope |
| Availability | No supervisor, cluster, failover, or durable event queue |
| Identity | Optional bearer API token; no accounts or roles |

## Development direction

Identified needs include integration lifecycle wiring, packet-byte capture, codec ownership, and explicit UI-to-runtime configuration mapping. Per-link execution requires separate stream contexts, codec and attack state isolation, and concurrency-safe integration handling. These are engineering needs, not a committed roadmap.

Source: [main window](../gui/main_window.py), [attack engine](../core/attack_engine.py), [integration manager](../core/integration_manager.py).
