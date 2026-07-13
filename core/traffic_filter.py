"""
core/traffic_filter.py
======================
Packet filter rules for selectively applying attacks.

A TrafficFilter holds a list of FilterRule objects.
Each rule specifies one or more match criteria (AND logic within a rule).
Multiple rules are combined with OR logic — if ANY rule matches, the
filter passes.

If no rules are configured, the filter matches ALL packets.

Usage:
    f = TrafficFilter()
    f.add_rule(src_ip="127.0.0.1", dst_port=4713)
    # Now only packets from 127.0.0.1 destined for port 4713 are attacked.

    f.add_rule(dst_port=4714)
    # Adding another rule: now ALSO attack traffic to port 4714.

    packet_info = {"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1",
                   "src_port": 4712, "dst_port": 4713, "proto": "UDP"}
    if f.matches(packet_info):
        # apply attack
        pass
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, List

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# FilterRule
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FilterRule:
    """
    A single filter rule. All specified fields must match (AND logic).
    Fields left as None are wildcards — they match anything.

    Attributes
    ----------
    src_ip    : source IP address string (e.g. "192.168.1.10"), or None
    dst_ip    : destination IP address string, or None
    src_port  : source UDP/TCP port, or None
    dst_port  : destination UDP/TCP port, or None
    proto     : protocol string: "UDP", "TCP", or None for any
    label     : human-readable rule label (for display)
    enabled   : if False, this rule is skipped
    """
    src_ip:   Optional[str] = None
    dst_ip:   Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto:    Optional[str] = None
    label:    str           = ""
    enabled:  bool          = True

    def matches(self, packet_info: dict) -> bool:
        """
        Check if this rule matches a given packet_info dict.

        packet_info keys (all optional):
          src_ip, dst_ip, src_port, dst_port, proto

        Returns True if ALL non-None rule fields match.
        """
        if not self.enabled:
            return False

        checks = [
            (self.src_ip,   packet_info.get("src_ip")),
            (self.dst_ip,   packet_info.get("dst_ip")),
            (self.proto,    packet_info.get("proto")),
        ]
        for rule_val, pkt_val in checks:
            if rule_val is not None:
                if pkt_val is None:
                    return False
                if str(rule_val).upper() != str(pkt_val).upper():
                    return False

        port_checks = [
            (self.src_port, packet_info.get("src_port")),
            (self.dst_port, packet_info.get("dst_port")),
        ]
        for rule_port, pkt_port in port_checks:
            if rule_port is not None:
                if pkt_port is None:
                    return False
                if int(rule_port) != int(pkt_port):
                    return False

        return True

    def to_dict(self) -> dict:
        return {
            "src_ip":   self.src_ip,
            "dst_ip":   self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto":    self.proto,
            "label":    self.label,
            "enabled":  self.enabled,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FilterRule":
        return cls(
            src_ip   = d.get("src_ip"),
            dst_ip   = d.get("dst_ip"),
            src_port = d.get("src_port"),
            dst_port = d.get("dst_port"),
            proto    = d.get("proto"),
            label    = d.get("label", ""),
            enabled  = d.get("enabled", True),
        )

    def __str__(self) -> str:
        parts = []
        if self.src_ip:   parts.append(f"src_ip={self.src_ip}")
        if self.dst_ip:   parts.append(f"dst_ip={self.dst_ip}")
        if self.src_port: parts.append(f"src_port={self.src_port}")
        if self.dst_port: parts.append(f"dst_port={self.dst_port}")
        if self.proto:    parts.append(f"proto={self.proto}")
        rule_str = " AND ".join(parts) if parts else "* (match all)"
        status   = "" if self.enabled else " [DISABLED]"
        label    = f"[{self.label}] " if self.label else ""
        return f"{label}{rule_str}{status}"


# ─────────────────────────────────────────────────────────────────────────────
# TrafficFilter
# ─────────────────────────────────────────────────────────────────────────────

class TrafficFilter:
    """
    Manages a list of FilterRules.

    Matching semantics:
    - If rules list is EMPTY → match ALL traffic (no filtering).
    - If rules list is non-empty → match if ANY enabled rule matches (OR logic
      across rules, AND logic within each rule).

    This allows "attack everything by default" when no filter is configured,
    and "attack only specific flows" when rules are added.
    """

    def __init__(self):
        self._rules: List[FilterRule] = []

    # ── Rule management ───────────────────────────────────────────────────────

    def add_rule(
        self,
        src_ip:   Optional[str] = None,
        dst_ip:   Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        proto:    Optional[str] = None,
        label:    str           = "",
    ) -> FilterRule:
        """
        Add a new filter rule and return it.

        All parameters are optional wildcards. A rule with all None fields
        matches everything.
        """
        rule = FilterRule(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            proto=proto, label=label or f"Rule {len(self._rules)+1}",
        )
        self._rules.append(rule)
        logger.debug(f"TrafficFilter: added rule {rule}")
        return rule

    def remove_rule(self, rule: FilterRule) -> None:
        if rule in self._rules:
            self._rules.remove(rule)

    def clear_rules(self) -> None:
        self._rules.clear()
        logger.debug("TrafficFilter: all rules cleared")

    @property
    def rules(self) -> List[FilterRule]:
        return list(self._rules)

    # ── Matching ──────────────────────────────────────────────────────────────

    def matches(self, packet_info: dict) -> bool:
        """
        Returns True if this packet should have the attack applied.

        Parameters
        ----------
        packet_info : dict with optional keys:
            src_ip (str), dst_ip (str), src_port (int),
            dst_port (int), proto (str)

        Returns
        -------
        bool
        """
        if not self._rules:
            # No rules → match everything
            return True

        for rule in self._rules:
            if rule.enabled and rule.matches(packet_info):
                logger.debug(f"TrafficFilter: packet matched rule [{rule.label}]")
                return True

        return False

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_list(self) -> list:
        return [r.to_dict() for r in self._rules]

    @classmethod
    def from_list(cls, data: list) -> "TrafficFilter":
        tf = cls()
        for d in data:
            tf._rules.append(FilterRule.from_dict(d))
        return tf

    def __repr__(self) -> str:
        if not self._rules:
            return "TrafficFilter(match_all)"
        return f"TrafficFilter([{', '.join(str(r) for r in self._rules)}])"


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("traffic_filter self-test")

    f = TrafficFilter()

    # Empty filter → match all
    pkt = {"src_ip": "192.168.1.10", "dst_ip": "127.0.0.1", "dst_port": 4713, "proto": "UDP"}
    assert f.matches(pkt), "Empty filter should match all"
    print("✔ Empty filter matches all")

    # Add specific rule
    r1 = f.add_rule(dst_port=4713, proto="UDP", label="PMU→PDC")
    assert f.matches(pkt), "Rule should match port 4713 UDP"
    print("✔ Matching rule passes")

    # Non-matching packet
    pkt2 = {"src_ip": "10.0.0.1", "dst_port": 9999, "proto": "TCP"}
    assert not f.matches(pkt2), "Should not match different port/proto"
    print("✔ Non-matching packet rejected")

    # Add second rule → OR logic
    r2 = f.add_rule(src_ip="10.0.0.1", label="Alt-source")
    assert f.matches(pkt2), "pkt2 matches second rule"
    print("✔ OR logic across rules works")

    # Disable rule
    r2.enabled = False
    assert not f.matches(pkt2), "Disabled rule should not match"
    print("✔ Disabled rule skipped")

    # Serialization round-trip
    data = f.to_list()
    f2   = TrafficFilter.from_list(data)
    assert len(f2.rules) == 2
    assert f2.rules[0].dst_port == 4713
    print("✔ Serialization round-trip OK")

    print("\ntraffic_filter ALL TESTS PASSED ✔")
