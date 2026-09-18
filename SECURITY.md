# Security model and reporting

GridSec Sim is a local research and training application for authorized laboratory use. The current implementation has no production security certification or published supported-version/security-response policy.

## Trust boundaries

- Topology input and attack parameters influence diagram state and, for selected fields, network destinations or transformations.
- Run attempts DNP3 and Modbus services plus a Linux raw Ethernet GOOSE publisher in addition to the C37.118 stream.
- The optional REST API can expose status, records, exports, and hook-based attack control. `/api/v1/status` is public even when bearer authentication is enabled.
- Exported measurements and recorded incidents are synthetic experimental data; desktop endpoint metadata is not a faithful packet capture.

## Existing controls and gaps

The desktop binds its C37.118 proxy to loopback. The core API defaults to loopback and bearer auth, but the manager configuration default is `0.0.0.0`. DNP3 requests an all-interface UDP bind. Explicitly choose intended addresses and a controlled network environment.

Protocol streams and API HTTP are unencrypted. There is no user/role system, token expiry, request rate limit, durable audit trail, or hardened request validation. API tokens are logged at INFO. CORS is permissive. Syslog has no TLS or durable delivery queue. The `cryptography` dependency does not enable these controls automatically.

Keep local interfaces on loopback where practical. Protect logs containing tokens. Use a dedicated lab environment for Layer 2/raw-socket work instead of granting broad privileges to a general-purpose Python installation. Save work before opening untrusted/malformed topology files because the loader clears the canvas before rebuilding it.

Current source-confirmed gaps are tracked in [Known limitations](docs/known-limitations.md); operational guidance is in [Operations](docs/operations.md).

## Report a security issue

No dedicated security email or private reporting URL is configured in this checkout. Contact the project maintainer through an existing trusted private channel, or use private vulnerability reporting if it is enabled on the actual hosting repository. Do not invent or assume a contact address.

Provide the affected revision, minimal reproduction, impact, and redacted evidence. Exclude API tokens and real infrastructure identifiers. No response or remediation timeline is promised by this document.

## Licensing status

Earlier project text says MIT, but an authoritative `LICENSE` file and copyright notice are absent. This document does not create a license or additional legal terms.
