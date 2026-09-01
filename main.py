"""
main.py
=======
GridSec Sim — Application Entry Point.

Usage:
    source venv/bin/activate
    python main.py

Optional environment variables:
    GRIDSEC_LOG_LEVEL=DEBUG   (default: INFO)
    DISPLAY=:0                (required on Linux/WSL2 without WSLg)
"""

import logging
import os
import sys
import traceback
from pathlib import Path

# ── Add project root to path ─────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.resolve()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ── Logging setup ─────────────────────────────────────────────────────────────
LOG_LEVEL = os.environ.get("GRIDSEC_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("gridsec")


def _check_dependencies() -> bool:
    """Verify all required packages are installed before importing Qt."""
    missing = []
    required = {
        "PyQt6":      "PyQt6>=6.4.0",
        "matplotlib": "matplotlib>=3.7.0",
        "numpy":      "numpy>=1.24.0",
    }
    for mod, req in required.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(req)

    if missing:
        print("=" * 60)
        print("  GridSec Sim — Missing Dependencies")
        print("=" * 60)
        print("\nThe following packages are required:")
        for m in missing:
            print(f"  • {m}")
        print("\nInstall them with:")
        print("  bash install.sh")
        print("  -- or --")
        print("  pip install -r requirements.txt")
        print()
        return False
    return True


def _crash_handler(exc_type, exc_value, exc_tb) -> None:
    """Global exception handler — shows dialog and logs the crash."""
    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    logger.critical(f"Unhandled exception:\n{error_msg}")

    # Try to show a Qt dialog if the app is running
    try:
        from PyQt6.QtWidgets import QApplication, QMessageBox
        app = QApplication.instance()
        if app:
            msg = QMessageBox()
            msg.setWindowTitle("GridSec Sim — Unexpected Error")
            msg.setIcon(QMessageBox.Icon.Critical)
            msg.setText(f"An unexpected error occurred:\n\n{exc_value}")
            msg.setDetailedText(error_msg)
            msg.exec()
    except Exception:
        pass

    sys.__excepthook__(exc_type, exc_value, exc_tb)


def main() -> int:
    """Main entry point — returns exit code."""

    logger.info("GridSec Sim starting up…")
    logger.info(f"Python {sys.version}")
    logger.info(f"Project root: {PROJECT_ROOT}")

    # Dependency check
    if not _check_dependencies():
        return 1

    # Import Qt after dependency check
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtGui import QFont

    # Enable High DPI scaling (PyQt6 handles this automatically)
    # On Linux, set QT_QPA_PLATFORM if no display is found
    if sys.platform.startswith("linux"):
        display = os.environ.get("DISPLAY", "")
        wayland = os.environ.get("WAYLAND_DISPLAY", "")
        if not display and not wayland:
            # Try xcb fallback
            os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
            logger.warning(
                "No DISPLAY or WAYLAND_DISPLAY set. "
                "Set DISPLAY=:0 or use WSLg for GUI output. "
                "Running in offscreen mode for testing."
            )

    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("GridSec Sim")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("GridSec")

    # Install crash handler
    sys.excepthook = _crash_handler

    # Default font
    try:
        font = QFont("Segoe UI", 13)
        app.setFont(font)
    except Exception:
        pass

    # Create and show main window
    from gui.main_window import MainWindow
    window = MainWindow()
    window.show()

    # WSLg can start a Wayland window behind the current desktop window.  Ask
    # the compositor to present it after the event loop begins as well.
    def _present_window() -> None:
        window.raise_()
        window.activateWindow()

    QTimer.singleShot(150, _present_window)

    # Useful for guided demos and quick verification without changing the
    # normal empty-canvas startup experience.
    if "--demo" in sys.argv:
        QTimer.singleShot(0, window._load_mitm_demo)

    logger.info("GridSec Sim GUI launched ✔")
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
