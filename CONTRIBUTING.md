# Contributing to GridSec Sim

Start with the [Developer guide](docs/development.md) and [Known limitations](docs/known-limitations.md). This repository does not yet define a formal maintainer roster, support SLA, contributor agreement, or release process.

## Local workflow

1. Use a dedicated environment and run the current regression suite before changing behavior.
2. Keep the change focused and preserve unrelated work.
3. Test the actual behavior affected: codec bytes, attack outcome, UI synchronization, topology round-trip, or integration lifecycle.
4. Update user/reference documentation when a setting, schema, route, or supported workflow changes.
5. Provide a review description covering the problem, resulting behavior, validation, and remaining limitations.

See [Testing](docs/testing.md) for portable commands. Do not run `test_launch.sh` or deployment helpers without inspecting their source-copying behavior and fixed paths.

## Bug reports

Include source revision, OS/Python/package versions, reproduction steps, expected/actual behavior, a minimal topology where relevant, and redacted logs. Distinguish GUI observations from independently verified network receipt. Identify whether a problem affects a documented limitation or a previously working path.

For sensitive security findings, follow [Security](SECURITY.md). Do not include API tokens, private receiver details, or unrelated production data in public reports.

## Contribution boundaries

Use synthetic fixtures and loopback or explicitly authorized lab endpoints. Keep codecs usable without Qt. Preserve portable topology identifiers and compatibility deliberately. Avoid adding dependencies without documenting their purpose and installation impact.

Licensing remains unresolved until the maintainer supplies the authoritative `LICENSE` and copyright notice; the former README's MIT statement is not a substitute for that file.
