# Data formats

[Documentation index](index.md)

## Topology JSON version 2

New saves contain:

```json
{
  "format": "GridSecSim",
  "version": 2,
  "nodes": [],
  "links": []
}
```

See the [complete example](examples/topology-v2.json) and [JSON Schema](reference/topology-v2.schema.json). The schema describes portable v2 documents for tooling; the application loader does not validate against it or enforce `format`/`version`.

### Nodes

| Field | Type | Meaning |
|---|---|---|
| `id` | String | Stable topology identifier; new nodes use UUID strings; legacy IDs may become numeric strings |
| `node_type` | String | Registered node type |
| `label` | String | Display name |
| `ip` | String | Configured endpoint/diagram IP |
| `port` | Integer | Port metadata or runtime endpoint, depending on node |
| `proto` | String | Saved transport, normally UDP/TCP |
| `level` | Integer | Diagram level -1 through 3 |
| `x`, `y` | Number | Scene coordinates |
| Other fields | Varies | Type-specific configuration |

Registered type strings: `CT_VT`, `BREAKER`, `PMU`, `PROTECTION_IED`, `BCU`, `PDC`, `SWITCH`, `STATION_HMI`, `ENGINEERING_WS`, `GATEWAY_RTU`, `STATE_PDC`, `THREAT_AGENT`, `VIRTUAL`.

Examples of additional fields are PMU `reporting_rate`/`idcode`, PDC `buffer_timeout`/`pmu_input_count`, breaker `state`, switch `port_count`, engineering workstation `high_risk`, gateway `protocol`, and State PDC `regional_uplink_connected`.

Threat Agents may contain `active`, `attack_type`, `attack_params`, and `attack_schedule` (`start_frame`, `duration_frames`). `intercepted_link` is an in-process object ID that can appear in metadata; treat the link's `threat_agent_ids` as the portable relationship. `running`/`active` are visual state snapshots, not instructions to launch a process on load.

### Links

| Field | Type | Meaning |
|---|---|---|
| `src_id`, `dst_id` | String | References to node IDs |
| `protocol` | String | C37.118, DNP3, Modbus, IEC104, or GOOSE |
| `threat_agent_ids` | Array of strings | Attached Threat Agent node IDs |

IDs must be unique, endpoints must exist, and attachment references should identify Threat Agents. JSON Schema cannot by itself enforce those cross-references; a semantic check is also required.

### Legacy compatibility

Legacy files may omit format/version and identify nodes with `_id`, often integers. The loader accepts `id` or `_id`, maps both original and string representations, restores resolvable links, then restores Threat Agent attachments. The bundled demo is a legacy-shaped file with attachment references; saving through the canvas converts it to v2.

Missing endpoints cause a link to be skipped. Missing attachment references are ignored. Duplicate IDs can redirect references to the last mapped node. Loading clears the existing canvas first, so malformed input can leave an empty or partial diagram. Save current work before opening unfamiliar files.

## Decoded C37.118 data

`parse_frame()` returns a dict or `None`. A decoded DATA dictionary includes:

| Field | Representation |
|---|---|
| `frame_type` | `data` |
| `sync`, `framesize`, `idcode` | Integer header values |
| `soc`, `fracsec` | Integer wire timestamp fields |
| `stat` | Integer status word |
| `phasors` | List of magnitude/angle pairs; angles in radians |
| `freq`, `dfreq` | Hz and Hz/s |
| `analog` | List of float values |
| `digital` | List of unsigned 16-bit words |
| `crc` | Parsed CRC integer |
| `raw` | Original Python `bytes` |

Other parser classifications include `cfg2`, `command`, `data_invalid`, `cfg_invalid`, `cmd_invalid`, and `unknown`; configuration detection also recognizes cfg1/cfg3. `rebuild_frame()` encodes data using the active codec and otherwise returns the stored `raw` bytes.

## PacketRecord

The proxy's internal record has exactly these slots: `timestamp`, `original`, `modified`, `status`, `attack_type`, `description`, `src_addr`.

`timestamp` is local wall time when proxy processing begins; `src_addr` is the received socket address. There is no `raw_bytes` slot. Raw data can exist inside the frame dictionary's `raw`, but the current GUI does not use that as capture input. Modified dictionaries can still contain original raw bytes, so blindly using that field would not provide the rebuilt wire output.

## Incident format

`Incident.as_dict()` exports:

| Field | Type/meaning |
|---|---|
| `id` | Eight-character UUID-derived string; not a durable globally unique event cursor |
| `timestamp` | Epoch seconds as float |
| `timestamp_iso` | UTC ISO-formatted timestamp |
| `protocol` | Protocol label, e.g. C37.118 |
| `src_ip`, `dst_ip` | Recorded addresses |
| `attack_type` | Module name or NONE for unclassified clean records |
| `status` | clean / attacked / dropped / invalid |
| `severity` | INFO / LOW / MEDIUM / HIGH; CRITICAL exists as a model value |
| `description` | Generated event description |
| `original_val`, `modified_val` | Serialized frame dictionaries |

The desktop currently supplies synthetic addresses `10.0.0.1` and `10.0.0.2`, source port 49000, destination port 4712, and protocol C37.118 to the integration manager, regardless of actual sockets. Do not use these fields as network-capture evidence.

Frame serialization stringifies values such as Python bytes; it does not define a base64 binary contract. Use actual PCAP bytes for packet reconstruction.

## Export containers

JSON export has `session_id`, `exported_at`, and `incidents`. CSV column order is:

```text
id,timestamp_iso,protocol,src_ip,dst_ip,attack_type,status,severity,description
```

Recent packet API entries contain `timestamp`, `protocol`, `status`, `attack`, `src`, `dst`, and `len`. `src`/`dst` are address-and-port strings; `len` is the length of supplied raw bytes, currently zero for the GUI path.

The REST incident response adds `count` and `total`; packet response adds `count`. Exported STIX and PCAP semantics are described in [Integrations](integrations.md).

Source: [canvas persistence](../gui/canvas.py), [node configurations](../gui/node_types.py), [parser](../core/packet_parser.py), [PacketRecord](../core/pdc_proxy.py), [incidents](../core/integration_manager.py).
