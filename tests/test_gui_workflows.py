"""Qt workflow checks. Run with QT_QPA_PLATFORM=offscreen for headless CI."""
import copy
import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PyQt6.QtCore import QPointF, Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QMessageBox

from core.attack_engine import AttackType
from gui.canvas import TopologyCanvas
from gui.main_window import MainWindow
from gui.node_types import NodeType
from gui.integration_panel import CaptureTab, SyslogTab, RestAPITab
from core.pdc_proxy import PDCProxy, PacketRecord


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = MainWindow()
        self.window._load_mitm_demo()
        self.app.processEvents()

    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()

    def test_attack_selection_and_sync_does_not_overwrite_parameters(self):
        w = self.window
        w._select_attack(AttackType.SCALE)
        self.assertEqual(w._attack_panel._get_active_type(), AttackType.SCALE)
        self.assertFalse(w._engine.is_enabled)
        w._engine.set_attack(AttackType.SCALE, {"scale_factor": 3.75})
        w._engine.set_schedule(15, 30)
        before = w._engine.snapshot()
        w._attack_panel.sync_from_engine()
        self.assertEqual(w._engine.snapshot(), before)
        self.assertEqual(w._attack_panel._get_current_params()["scale_factor"], 3.75)
        w._attack_panel.select_attack(AttackType.DROP)
        self.assertEqual(w._engine.active_type, AttackType.DROP)
        self.assertTrue(w._engine.is_enabled)
        QTest.mouseClick(w._attack_panel._enable_btn, Qt.MouseButton.LeftButton)
        self.assertFalse(w._engine.is_enabled)

    def test_atomic_save_restore_attack_positions_and_agents(self):
        w = self.window
        node = w._canvas.get_pmu_nodes()[0]
        node.setPos(QPointF(123, 234))
        w._engine.set_attack(AttackType.FREQUENCY_OVERRIDE, {"target_freq": 59})
        w._engine.set_schedule(12, 45)
        w._attack_panel.sync_from_engine()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "saved.json"
            w.save_topology_to(path)
            data = json.loads(path.read_text())
            w._load_quick_scenario("Clean", AttackType.NONE, {})
            w._load_topology_data(data)
            self.assertEqual(w._engine.active_type, AttackType.FREQUENCY_OVERRIDE)
            self.assertEqual(w._engine.get_params()["target_freq"], 59)
            self.assertTrue(w._engine.is_enabled)
            self.assertEqual(w._engine.schedule, {"start_frame": 12, "duration_frames": 45})
            self.assertEqual(w._canvas.get_pmu_nodes()[0].pos(), QPointF(123, 234))
            self.assertTrue(w._canvas.get_intercepted_links())

    def test_bad_topology_is_transactional(self):
        w = self.window
        before = w._serialize_topology()
        for mutate in (
            lambda d: d["nodes"][0].update(node_type="BOGUS"),
            lambda d: d["nodes"][0].update(x=float("nan")),
            lambda d: d["links"][0].update(dst_id="missing"),
            lambda d: d.update(simulation={"type": "BOGUS"}),
            lambda d: d["nodes"].append(copy.deepcopy(d["nodes"][0])),
        ):
            bad = copy.deepcopy(before)
            mutate(bad)
            with self.assertRaises(ValueError):
                w._load_topology_data(bad)
            self.assertEqual(w._serialize_topology(), before)

    def test_canvas_signals_and_movements_are_instance_local(self):
        other = TopologyCanvas()
        changes = []
        other.signals.topology_changed.connect(lambda: changes.append(True))
        self.window._canvas.add_node(NodeType.VIRTUAL)
        self.assertEqual(changes, [])
        other.deleteLater()

    def test_integration_buttons_start_stop_real_services(self):
        w = self.window
        manager = w._integration
        with tempfile.TemporaryDirectory() as folder:
            capture = w.findChild(CaptureTab)
            capture._path_edit.setText(str(Path(folder) / "test.pcap"))
            capture._start_capture()
            self.assertTrue(manager._pcap.is_active)
            capture._stop_capture()
            self.assertTrue(Path(manager.pcap_path).exists())
            api = w.findChild(RestAPITab)
            api._host.setText("127.0.0.1")
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            api._port.setValue(port)
            api._start()
            self.assertIsNotNone(manager._rest)
            self.assertTrue(api._stop_btn.isEnabled())
            api._stop()
            self.assertIsNone(manager._rest)
            syslog = w.findChild(SyslogTab)
            syslog._enable()
            self.assertIsNotNone(manager._syslog)
            syslog._disable()
            self.assertIsNone(manager._syslog)

    def test_real_simulation_stop_restart_and_running_guards(self):
        w = self.window
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            proxy_port = reserve.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
            sink.bind(("127.0.0.1", 0))
            sink.settimeout(2)
            w._canvas.get_pmu_nodes()[0]._config.update(port=proxy_port, reporting_rate=10, idcode=7)
            w._canvas.get_pdc_nodes()[0]._config.update(port=sink.getsockname()[1])
            for _ in range(2):
                w._engine.set_attack(AttackType.SCALE, {"scale_factor": 2})
                w._attack_panel.sync_from_engine()
                with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
                    w._start_simulation()
                self.assertTrue(w._sim_running)
                pmu, proxy = w._pmu, w._proxy
                self.assertEqual(pmu.fps, 10)
                self.assertEqual(pmu.idcode, 7)
                QTest.qWait(200)
                self.assertGreater(w._engine.stats["modified_packets"], 0)
                before = w._serialize_topology()
                with patch.object(QMessageBox, "warning"):
                    w._open_topology()
                    w._load_quick_scenario("Clean", AttackType.NONE, {})
                self.assertEqual(w._serialize_topology(), before)
                start = time.monotonic()
                w._stop_simulation()
                self.assertLess(time.monotonic() - start, 2)
                self.assertFalse(pmu.is_alive())
                self.assertFalse(proxy.is_alive())
                self.assertFalse(w._integration.sim_running)

    def test_remote_hooks_keep_engine_and_panel_in_sync(self):
        w = self.window
        # Exercise the same backend hooks used by the HTTP server.
        import threading
        worker = threading.Thread(target=lambda: w._integration._api_enable_attack(
            "MAGNITUDE_OVERRIDE", {"phasor_idx": 0, "value": 25}))
        worker.start()
        worker.join(1)
        self.app.processEvents()
        self.assertTrue(w._engine.is_enabled)
        self.assertEqual(w._attack_panel._get_active_type(), AttackType.MAGNITUDE_OVERRIDE)
        self.assertEqual(w._attack_panel._get_current_params()["value"], 25)
        self.assertTrue(w._integration._api_disable_attack())
        self.app.processEvents()
        self.assertFalse(w._attack_panel.is_attack_enabled())

    def test_selected_link_scope_is_enforced(self):
        w = self.window
        proxy = PDCProxy(attack_engine=w._engine)
        w._proxy = proxy
        try:
            w._attack_panel._scope_sel.setChecked(True)
            w._selected_link = None
            w._update_attack_scope()
            self.assertFalse(proxy.attack_enabled)
            link = w._canvas.get_all_links()[0]
            w._on_link_selected(link)
            self.assertTrue(proxy.attack_enabled)
            w._selected_link = None
            w._attack_panel._scope_all.setChecked(True)
            self.assertTrue(proxy.attack_enabled)
        finally:
            w._proxy = None

    def test_control_frames_and_drops_do_not_make_fake_waveforms(self):
        w = self.window
        initial = w._waveform._frame_count
        cfg = PacketRecord(time.time(), {"frame_type": "cfg2"}, {}, "clean")
        w._waveform.push_frame_from_record(cfg)
        self.assertEqual(w._waveform._frame_count, initial)
        dropped = PacketRecord(time.time(), {"frame_type": "data", "freq": 50,
                                            "phasors": [[120, 0]]}, {}, "dropped")
        with patch.object(w._waveform, "push_frame") as push:
            w._waveform.push_frame_from_record(dropped)
            import math
            self.assertTrue(math.isnan(push.call_args.args[1]["freq"]))

    def test_startup_port_conflict_restores_ui(self):
        w = self.window
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(("127.0.0.1", 0))
            w._canvas.get_pmu_nodes()[0]._config["port"] = occupied.getsockname()[1]
            with patch.object(QMessageBox, "critical") as error:
                w._start_simulation()
                error.assert_called_once()
            self.assertFalse(w._sim_running)
            self.assertIsNone(w._proxy)
            self.assertTrue(w._tb_run.isEnabled())


if __name__ == "__main__":
    unittest.main()
