# Glossary

[Documentation index](index.md)

| Term | Meaning in this project |
|---|---|
| Attack engine | Applies one selected transformation to eligible decoded data frames |
| BCU | Bay Control Unit; a diagram node representing bay switching/control |
| C37.118 | Synchrophasor communication format targeted by the primary codec/runtime |
| CEF | Common Event Format used by the Syslog exporter |
| CFG-2 | Configuration frame describing measurement channels and reporting setup |
| CRC | Checksum used to detect frame corruption; recalculation does not authenticate a sender |
| CT/VT | Current/voltage transformer, represented as a process-level sensor node |
| DNP3 | Protocol family represented by framing helpers and a limited UDP simulator |
| Frame | Encoded protocol message, or its decoded dictionary when stated explicitly |
| GOOSE | IEC 61850-associated event-message format carried directly over Ethernet |
| HMI | Human-machine interface; station diagram asset in GridSec Sim |
| IDCODE | Identifier carried in C37.118 headers |
| IED | Intelligent Electronic Device; protection relay diagram type |
| Incident | Manager record for any processed callback, including clean traffic |
| Integration manager | Owns retained records, exporters, and optional external interfaces |
| Local PDC | Diagram destination used by the desktop proxy; does not start a receiver |
| MitM | Man in the middle; here, an explicitly configured local forwarding proxy |
| Modbus TCP | Register-oriented protocol served/polled by the auxiliary simulator |
| PacketRecord | Internal proxy record containing original/modified dicts and classification |
| PCAP | Packet capture file format; core writer creates synthesized network frames |
| PDC | Phasor Data Concentrator, an intended downstream measurement receiver |
| Phasor | Magnitude and phase angle representation of a periodic quantity |
| PMU | Phasor Measurement Unit; here, a synthetic measurement generator |
| ROCOF / DFREQ | Rate of change of frequency, represented in Hz/s |
| RTU | Remote Terminal Unit; gateway diagram type |
| SCADA | Supervisory Control and Data Acquisition |
| SIEM / SOAR | Security event analysis / response automation systems that may consume exports |
| SSE | Server-Sent Events, the API's optional live HTTP event stream |
| State PDC | Higher-level diagram node with a regional uplink indicator |
| STIX | Structured threat-information representation targeted by the experimental exporter |
| Threat Agent | Canvas node recording interception metadata; not an independent runtime engine |
| Topology | Saved diagram of nodes, links, and metadata |
| Traffic filter | Rules selecting frames for attack processing, not a network firewall |
| WSL | Windows Subsystem for Linux; a possible Linux runtime/display environment |

For support boundaries, consult [Protocols](protocols.md) and [Known limitations](known-limitations.md).
