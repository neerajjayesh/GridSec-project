# GridSec Sim documentation

**Application:** GridSec Sim 1.0.0  
**Project GitHub:** [neerajjayesh/GridSec-project](https://github.com/neerajjayesh/GridSec-project)

This set covers the GridSec Sim desktop application and its protocol, simulation, and integration components.

**[Complete PDF manual](../output/pdf/GridSec_Sim_Documentation.pdf)** - with clickable contents, architecture diagrams, complete worked examples, and reference files.

**[Overleaf project ZIP](../output/overleaf/GridSec_Sim_Overleaf.zip)** - upload to Overleaf and compile `main.tex` with pdfLaTeX.

## Guides and references

| Document | Purpose |
|---|---|
| [Product overview](overview.md) | Purpose, users, scope, and capability status |
| [Getting started](getting-started.md) | Requirements, installation, first run, and verification |
| [User guide](user-guide.md) | Topology editing, scenarios, plots, and experiment workflow |
| [Architecture](architecture.md) | Components, data flow, threads, and state ownership |
| [Configuration](configuration.md) | Launch options, environment, defaults, and persistence |
| [Attack reference](attacks.md) | Ten modules, parameters, scheduling, filters, and statistics |
| [Protocol reference](protocols.md) | C37.118, GOOSE, DNP3, Modbus, and IEC104 implementation |
| [REST API reference](api-reference.md) | Authentication, routes, payloads, errors, and restrictions |
| [Integrations](integrations.md) | PDC receivers, captures, Syslog/CEF, and exports |
| [Data formats](data-formats.md) | Topology schema, frames, packet records, and incident formats |
| [Operations and troubleshooting](operations.md) | Network footprint, diagnostics, and recovery |
| [Development](development.md) | Source organization and extension points |
| [Testing](testing.md) | Reproducible checks, results, and coverage boundaries |
| [Known limitations](known-limitations.md) | Confirmed gaps and practical consequences |
| [Glossary](glossary.md) | Project terminology |

## Reference artifacts

- [OpenAPI description](reference/openapi.json): machine-readable HTTP interface description.
- [Topology v2 JSON Schema](reference/topology-v2.schema.json): documentation schema; not enforced by the application loader.
- [Topology v2 example](examples/topology-v2.json): small PMU/Local PDC/Threat Agent diagram.
- [Offline frame example](examples/inspect_frame.py): generate, modify, rebuild, and decode without network traffic.
- [Local API example](examples/serve_api.py): serve a synthetic incident on loopback.
- [Contributing](../CONTRIBUTING.md), [Security](../SECURITY.md), [Changelog](../CHANGELOG.md).

## Reading paths

**Operator:** Getting started → User guide → Attacks → Operations.

**Developer:** Overview → Architecture → Configuration → Data formats → Development → Testing.

**Integration engineer:** Known limitations → Protocols → Integrations → REST API → Security.

## Conventions

Commands run from the repository root unless stated otherwise. `python` means the interpreter from the environment where you installed the project. Windows commands use PowerShell; Linux commands use a POSIX shell. Example measurements are illustrative.

“Implemented” means code exists for the stated behavior. “Desktop-wired” means the main window connects it to the GUI workflow. “Experimental” indicates that completeness or interoperability has not been established. Internal tests do not establish protocol conformance.

Source links identify implementation files to review when behavior changes. [SCENARIOS.md](../SCENARIOS.md) and [WHAT_WAS_ADDED.md](../WHAT_WAS_ADDED.md) retain historical context; this set takes precedence for current behavior.
