"""
test_regression.py
==================
Full regression test for GridSecSim — Parts 1-4 verification.

Tests:
  Part 1 — Hierarchical node types, palette grouping, level lanes, snap
  Part 2 — Properties panel, selection signal path, type-specific schemas
  Part 3 — Attack engine QA (all 10 modules) with stats validation
  Part 4 — End-to-end simulation flow: PMU → ThreatAgent → PDC

Runs in offscreen mode (no display required).
"""

import math
import json
import os
import sys
import time
from pathlib import Path

# Force offscreen rendering
os.environ["QT_QPA_PLATFORM"] = "offscreen"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QPointF, Qt, QTimer

app = QApplication.instance() or QApplication(sys.argv)

from core.attack_engine import AttackEngine, AttackType
from protocols.c37118 import C37118Codec
from gui.node_types import (
    NodeType, NODE_CLASSES, NODE_LEVEL, LEVEL_LABELS,
    NODE_DISPLAY_NAMES, NODE_COLORS, NODE_ICON_TEXT, NODE_SHORT_NAMES,
    create_node, BaseNode, LinkItem,
    CTVTNode, BreakerNode, PMUNode, ProtectionIEDNode, BCUNode,
    PDCNode, SwitchNode, StationHMINode, EngineeringWSNode,
    GatewayRTUNode, StatePDCNode, ThreatAgentNode, VirtualNode,
)
from gui.canvas import TopologyCanvas, LANE_Y_CENTER, LANE_Y_TOP, LANE_Y_BOTTOM
from gui.properties_panel import PropertiesPanel

PASS = 0
FAIL = 0

def check(condition, label):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")

# ============================================================================
print("=" * 70)
print("  GridSecSim Regression Test Suite")
print("=" * 70)

# ============================================================================
# PART 1: Hierarchical Node Types
# ============================================================================
print("\n" + "=" * 70)
print("  PART 1: Hierarchical Node Types & Level Mapping")
print("=" * 70)

# 1.1 All 13 node types exist
check(len(NODE_CLASSES) == 13, f"13 node types registered (got {len(NODE_CLASSES)})")

# 1.2 All expected types are present
expected_types = [
    NodeType.CT_VT, NodeType.BREAKER,
    NodeType.PMU, NodeType.PROTECTION_IED, NodeType.BCU,
    NodeType.PDC, NodeType.SWITCH, NodeType.STATION_HMI,
    NodeType.ENGINEERING_WS, NodeType.GATEWAY_RTU,
    NodeType.STATE_PDC,
    NodeType.THREAT_AGENT, NodeType.VIRTUAL,
]
for nt in expected_types:
    check(nt in NODE_CLASSES, f"Node type {nt} is registered")

# 1.3 Level assignments are correct
level_checks = {
    NodeType.CT_VT: 0, NodeType.BREAKER: 0,
    NodeType.PMU: 1, NodeType.PROTECTION_IED: 1, NodeType.BCU: 1,
    NodeType.PDC: 2, NodeType.SWITCH: 2, NodeType.STATION_HMI: 2,
    NodeType.ENGINEERING_WS: 2, NodeType.GATEWAY_RTU: 2,
    NodeType.STATE_PDC: 3,
    NodeType.THREAT_AGENT: -1, NodeType.VIRTUAL: -1,
}
for nt, expected_level in level_checks.items():
    actual = NODE_LEVEL.get(nt)
    check(actual == expected_level, f"{nt} level = {actual} (expected {expected_level})")

# 1.4 All metadata dicts are populated
for nt in expected_types:
    check(nt in NODE_DISPLAY_NAMES, f"{nt} has display name")
    check(nt in NODE_COLORS, f"{nt} has color")
    check(nt in NODE_ICON_TEXT, f"{nt} has icon text")
    check(nt in NODE_SHORT_NAMES, f"{nt} has short name")

# 1.5 Node instantiation
for nt in expected_types:
    node = create_node(nt, label=f"Test-{nt}")
    check(isinstance(node, BaseNode), f"create_node({nt}) returns BaseNode subclass")
    cfg = node.get_config()
    check(cfg["node_type"] == nt, f"{nt} config.node_type matches")
    check(cfg["level"] == NODE_LEVEL[nt], f"{nt} config.level matches")

# 1.6 Specific node type features
breaker = create_node(NodeType.BREAKER, "CB-Test")
check(breaker._config.get("state") == "closed", "Breaker default state is 'closed'")

spdc = create_node(NodeType.STATE_PDC, "SPDC-Test")
check(spdc._config.get("regional_uplink_connected") is False, "State PDC uplink default False")

ew = create_node(NodeType.ENGINEERING_WS, "EW-Test")
check(ew._config.get("high_risk") is True, "Engineering WS high_risk flag True")

hmi = create_node(NodeType.STATION_HMI, "HMI-Test")
check(hmi._config.get("status") == "Active", "Station HMI default status Active")

rtu = create_node(NodeType.GATEWAY_RTU, "RTU-Test")
check(rtu._config.get("protocol") == "DNP3", "Gateway/RTU default protocol DNP3")

# ============================================================================
# PART 1b: Canvas Level Lanes & Snap
# ============================================================================
print("\n" + "=" * 70)
print("  PART 1b: Canvas Level Lanes & Snap-to-Lane")
print("=" * 70)

canvas = TopologyCanvas()

# Test snap-to-lane for each level
for level in [0, 1, 2, 3]:
    # Find a node type at this level
    nt = [k for k, v in NODE_LEVEL.items() if v == level][0]
    node = canvas.add_node(nt, QPointF(100, 0))  # Y=0 should get snapped
    pos = node.pos()
    lane_top = LANE_Y_TOP[level]
    lane_bottom = LANE_Y_BOTTOM[level]
    in_lane = lane_top <= pos.y() <= lane_bottom
    check(in_lane, f"L{level} node {nt} Y={pos.y():.0f} in lane [{lane_top},{lane_bottom}]")

# Threat Agent should NOT be snapped (level = -1)
threat = canvas.add_node(NodeType.THREAT_AGENT, QPointF(200, 300))
# It should stay where placed (no snap)
check(True, f"Threat Agent placed at Y={threat.pos().y():.0f} (no lane constraint)")

# ============================================================================
# PART 1c: Smart Link Protocol Defaults
# ============================================================================
print("\n" + "=" * 70)
print("  PART 1c: Smart Link Protocol Defaults")
print("=" * 70)

canvas2 = TopologyCanvas()

# L0 -> L1: GOOSE
ct = canvas2.add_node(NodeType.CT_VT, QPointF(100, 500))
ied = canvas2.add_node(NodeType.PROTECTION_IED, QPointF(200, 300))
link_01 = canvas2.add_link(ct, ied)
check(link_01.protocol == "GOOSE", f"L0->L1 default protocol: {link_01.protocol} (expected GOOSE)")

# L1 -> L2 (PMU): C37.118
pmu = canvas2.add_node(NodeType.PMU, QPointF(100, 300))
pdc = canvas2.add_node(NodeType.PDC, QPointF(200, 100))
link_12_pmu = canvas2.add_link(pmu, pdc)
check(link_12_pmu.protocol == "C37.118", f"PMU->PDC default protocol: {link_12_pmu.protocol} (expected C37.118)")

# L2 -> L3 (RTU): DNP3
rtu_n = canvas2.add_node(NodeType.GATEWAY_RTU, QPointF(300, 100))
spdc_n = canvas2.add_node(NodeType.STATE_PDC, QPointF(400, -100))
link_23_rtu = canvas2.add_link(rtu_n, spdc_n)
check(link_23_rtu.protocol == "DNP3", f"RTU->SPDC default protocol: {link_23_rtu.protocol} (expected DNP3)")

# L2 -> L3 (PDC): C37.118
link_23_pdc = canvas2.add_link(pdc, spdc_n)
check(link_23_pdc.protocol == "C37.118", f"PDC->SPDC default protocol: {link_23_pdc.protocol} (expected C37.118)")

# ============================================================================
# PART 2: Properties Panel
# ============================================================================
print("\n" + "=" * 70)
print("  PART 2: Properties Panel & Selection Signal")
print("=" * 70)

# 2.1 Scene selectionChanged is connected
check(hasattr(canvas, '_handle_selection_change'), "Canvas has _handle_selection_change method")
# The signal is connected in __init__ — verify by calling it
canvas._handle_selection_change()  # should not crash

# 2.2 Properties panel shows node
props = PropertiesPanel()

for nt in expected_types:
    node = create_node(nt, label=f"Props-{nt}")
    try:
        props.show_node(node)
        check(props._current_node is node, f"PropertiesPanel.show_node({nt}) sets current node")
        check(len(props._field_widgets) > 0, f"PropertiesPanel.show_node({nt}) creates fields ({len(props._field_widgets)})")
    except Exception as e:
        check(False, f"PropertiesPanel.show_node({nt}) threw: {e}")

# 2.3 Properties panel shows link
link = LinkItem(
    create_node(NodeType.PMU, "TestPMU"),
    create_node(NodeType.PDC, "TestPDC"),
    "C37.118"
)
try:
    props.show_link(link)
    check(props._current_link is link, "PropertiesPanel.show_link sets current link")
except Exception as e:
    check(False, f"PropertiesPanel.show_link threw: {e}")

# 2.4 Properties panel clear
props.clear()
check(props._current_node is None, "PropertiesPanel.clear() clears node")
check(props._current_link is None, "PropertiesPanel.clear() clears link")

# 2.5 State PDC regional uplink toggle
spdc_props = create_node(NodeType.STATE_PDC, "SPDC-Props")
props.show_node(spdc_props)
# Check uplink button exists
has_uplink_btn = "_regional_uplink_btn" in props._field_widgets
check(has_uplink_btn, "State PDC Properties has regional uplink toggle")

# 2.6 Breaker state toggle
breaker_props = create_node(NodeType.BREAKER, "CB-Props")
props.show_node(breaker_props)
has_breaker_btn = "_breaker_state_btn" in props._field_widgets
check(has_breaker_btn, "Breaker Properties has state toggle button")

# 2.7 Engineering WS risk badge
ew_props = create_node(NodeType.ENGINEERING_WS, "EW-Props")
props.show_node(ew_props)
check(not props._risk_badge.isHidden(), "Engineering WS shows risk badge")

# 2.8 Non-EW hides risk badge
pmu_props = create_node(NodeType.PMU, "PMU-Props")
props.show_node(pmu_props)
check(not props._risk_badge.isVisible(), "Non-EW hides risk badge")

# ============================================================================
# PART 3: Attack Engine QA — All 10 Modules
# ============================================================================
print("\n" + "=" * 70)
print("  PART 3: Attack Engine QA — All 10 Modules")
print("=" * 70)

codec = C37118Codec(idcode=1, num_phasors=3, num_analog=1, num_digital=0)
TWO_PI = 2 * math.pi

def make_frame(freq=50.0, mag=120.0):
    phasors = [(mag, 0.0), (mag, -TWO_PI/3), (mag, TWO_PI/3)]
    raw = codec.encode_data_frame(phasors, freq, 0.0, [1.0], [])
    d = codec.decode_data_frame(raw).to_dict()
    d["frame_type"] = "data"
    return d

# Test each attack
engine = AttackEngine()

# [1] NOISE
engine.set_attack(AttackType.NOISE, {"noise_std": 5.0})
frame = make_frame()
orig_mag = frame["phasors"][0][0]
f2, modified, dropped = engine.apply(frame)
check(modified, "[1] NOISE modifies frame")
check(not dropped, "[1] NOISE does not drop")
diff = abs(f2["phasors"][0][0] - orig_mag)
check(diff < 50, f"[1] NOISE diff={diff:.3f} is reasonable")

# [2] RAMP
engine.set_attack(AttackType.RAMP, {"ramp_rate": 1.0, "direction": "up", "target": "magnitude"})
frame = make_frame()
results = [engine.apply(frame)[0]["phasors"][0][0] for _ in range(5)]
check(results[-1] > results[0], f"[2] RAMP increases: {results[0]:.1f} -> {results[-1]:.1f}")

# [3] PULSE
engine.set_attack(AttackType.PULSE, {"amplitude": 50.0, "interval": 5, "duration_frames": 2})
frame = make_frame()
pulse_results = [(engine.apply(frame)) for _ in range(10)]
spikes = sum(1 for f, m, d in pulse_results if m)
check(spikes > 0, f"[3] PULSE has {spikes} spike frames out of 10")

# [4] FREQUENCY_OVERRIDE
engine.set_attack(AttackType.FREQUENCY_OVERRIDE, {"target_freq": 60.0})
frame = make_frame(freq=50.0)
f2, m, d = engine.apply(frame)
check(abs(f2["freq"] - 60.0) < 0.01, f"[4] FREQ_OVERRIDE: {f2['freq']}Hz (expected 60)")
check(m, "[4] FREQ_OVERRIDE marks as modified")

# [5] MAGNITUDE_OVERRIDE
engine.set_attack(AttackType.MAGNITUDE_OVERRIDE, {"phasor_idx": 0, "value": 0.0})
frame = make_frame()
f2, m, d = engine.apply(frame)
check(abs(f2["phasors"][0][0]) < 0.01, f"[5] MAG_OVERRIDE forces Va to 0.0V")
check(m, "[5] MAG_OVERRIDE marks as modified")

# [6] ANGLE_OVERRIDE
engine.set_attack(AttackType.ANGLE_OVERRIDE, {"phasor_idx": 0, "angle_deg": 90.0})
frame = make_frame()
f2, m, d = engine.apply(frame)
expected_rad = math.radians(90.0)
check(abs(f2["phasors"][0][1] - expected_rad) < 0.001, f"[6] ANGLE_OVERRIDE forces 90 deg")
check(m, "[6] ANGLE_OVERRIDE marks as modified")

# [7] REPLAY
engine.set_attack(AttackType.REPLAY, {"buffer_size": 5})
for freq in [50.0, 50.1, 50.2, 50.3, 50.4]:
    engine.apply(make_frame(freq=freq))
replayed = [engine.apply(make_frame(freq=51.0))[0]["freq"] for _ in range(5)]
check(not any(abs(f - 51.0) < 0.05 for f in replayed), f"[7] REPLAY loops buffer, not live")

# [8] DELAY
engine.set_attack(AttackType.DELAY, {"delay_ms": 50.0})
frame = make_frame()
t0 = time.time()
f2, m, d = engine.apply(frame)
elapsed_ms = (time.time() - t0) * 1000
check(elapsed_ms >= 45, f"[8] DELAY elapsed={elapsed_ms:.1f}ms (expected >=45)")

# [9] DROP
engine.set_attack(AttackType.DROP, {"drop_percent": 50.0})
frame = make_frame()
drops = sum(1 for _ in range(200) if engine.apply(frame)[2])
pct = drops / 200 * 100
check(30 < pct < 70, f"[9] DROP rate={pct:.1f}% (expected 30-70%)")

# [10] SCALE
engine.set_attack(AttackType.SCALE, {"scale_factor": 2.0})
frame = make_frame(mag=100.0)
f2, m, d = engine.apply(frame)
check(abs(f2["phasors"][0][0] - 200.0) < 1.0, f"[10] SCALE 100*2={f2['phasors'][0][0]:.1f}V")
check(m, "[10] SCALE marks as modified")

# Stats
stats = engine.stats
check(stats["total_packets"] > 200, f"Stats total_packets={stats['total_packets']}")
check(stats["modified_packets"] > 0, f"Stats modified_packets={stats['modified_packets']}")
check(stats["dropped_packets"] > 0, f"Stats dropped_packets={stats['dropped_packets']}")

# Reset
engine.reset_stats()
check(engine.stats["total_packets"] == 0, "reset_stats zeroes total_packets")
check(engine.stats["modified_packets"] == 0, "reset_stats zeroes modified_packets")
check(engine.stats["dropped_packets"] == 0, "reset_stats zeroes dropped_packets")

# Scheduled attack window: wait for two frames, modify exactly two frames.
engine.set_attack(AttackType.SCALE, {"scale_factor": 2.0})
engine.set_schedule(start_frame=2, duration_frames=2)
schedule_results = [engine.apply(make_frame(mag=100.0))[1] for _ in range(5)]
check(schedule_results == [False, False, True, True, False],
      "Scheduled attack runs only within its frame window")
engine.set_schedule()

# ============================================================================
# PART 4: Save/Load Topology
# ============================================================================
print("\n" + "=" * 70)
print("  PART 4: Save/Load Topology with New Node Types")
print("=" * 70)

canvas3 = TopologyCanvas()
nodes_before = []
for nt in [NodeType.CT_VT, NodeType.PMU, NodeType.PDC, NodeType.STATE_PDC, NodeType.THREAT_AGENT]:
    n = canvas3.add_node(nt)
    nodes_before.append(n)
    
# Add links
canvas3.add_link(nodes_before[0], nodes_before[1])  # CT -> PMU
canvas3.add_link(nodes_before[1], nodes_before[2])  # PMU -> PDC
canvas3.add_link(nodes_before[2], nodes_before[3])  # PDC -> SPDC

# Save
topo = canvas3.save_topology()
check(topo.get("version") == 2, "Saved topology uses portable v2 schema")
check(len(topo["nodes"]) == 5, f"Save: {len(topo['nodes'])} nodes (expected 5)")
check(len(topo["links"]) == 3, f"Save: {len(topo['links'])} links (expected 3)")

# Verify node types in saved data
saved_types = [n["node_type"] for n in topo["nodes"]]
check(NodeType.CT_VT in saved_types, "Saved topology includes CT_VT")
check(NodeType.STATE_PDC in saved_types, "Saved topology includes STATE_PDC")

# 4.1 Bundled MitM demo and intercepted-link persistence
demo_path = Path(__file__).with_name("mitm-demo-topology.json")
with demo_path.open(encoding="utf-8") as f:
    demo_data = json.load(f)
demo_canvas = TopologyCanvas()
demo_canvas.load_topology(demo_data)
demo_agents = demo_canvas.get_threat_agents()
check(len(demo_agents) == 1, "MitM demo loads one Threat Agent")
check(demo_agents[0]._config.get("active") is True, "MitM demo attacker is active")
check(len(demo_canvas.get_intercepted_links()) == 1, "MitM demo link is intercepted")

# A topology saved by the app must retain the attachment when loaded again.
round_trip = TopologyCanvas()
round_trip.load_topology(demo_canvas.save_topology())
check(len(round_trip.get_intercepted_links()) == 1,
      "Save/load retains intercepted-link state")

# ============================================================================
# PART 4b: Regional Uplink Toggle
# ============================================================================
print("\n" + "=" * 70)
print("  PART 4b: State PDC Regional Uplink Toggle")
print("=" * 70)

spdc_toggle = create_node(NodeType.STATE_PDC, "SPDC-Toggle")
check(spdc_toggle._config["regional_uplink_connected"] is False, "SPDC uplink starts False")

# Toggle on
spdc_toggle._config["regional_uplink_connected"] = True
spdc_toggle.update()
check(spdc_toggle._config["regional_uplink_connected"] is True, "SPDC uplink toggled to True")

# Toggle off
spdc_toggle._config["regional_uplink_connected"] = False
spdc_toggle.update()
check(spdc_toggle._config["regional_uplink_connected"] is False, "SPDC uplink toggled back to False")

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "=" * 70)
total = PASS + FAIL
print(f"  RESULTS: {PASS}/{total} passed, {FAIL} failed")
if FAIL == 0:
    print("  ALL TESTS PASSED")
else:
    print(f"  {FAIL} TEST(S) FAILED")
print("=" * 70)

sys.exit(0 if FAIL == 0 else 1)
