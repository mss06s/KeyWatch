# app.py — v1 compact layout, centered toggle, fixed animation target lifetime
# -----------------------------------------------------------------------------
# KeyWatch (UI)
# - PySide6 desktop app
# - Threaded scanner so the UI never freezes
# - “Status Card” in the middle + “View details” modal
# - Fancy glow on the primary CTA because vibes matter
# -----------------------------------------------------------------------------

from PySide6.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QVBoxLayout,
    QGraphicsDropShadowEffect, QProgressBar, QCheckBox, QHBoxLayout, QFrame, QSizePolicy,
    QDialog, QTableWidget, QTableWidgetItem, QHeaderView, QDialogButtonBox
)
from PySide6.QtCore import Qt, QThread, QObject, Signal, Slot, QPropertyAnimation, QEasingCurve, QTimer
from PySide6.QtGui import QColor, QFont
import sys
from keywatch.detector import scan_system  # ← backend scanner (separate file)

# ------------------------------- Worker Thread -------------------------------
# Runs the scan off the main thread. Emits progress + final result back to UI.
class ScannerWorker(QObject):
    progress = Signal(str, int, int)  # (label, step_index, total_steps)
    finished = Signal(dict)           # full result payload from detector
    error = Signal(str)               # bubble up exceptions as text

    def __init__(self, include_tasks=False, include_processes=False, include_services=False, include_appdata_sweep=False):
        super().__init__()
        # toggles for “Deep scan” feature
        self.include_tasks = include_tasks
        self.include_processes = include_processes
        self.include_services = include_services
        self.include_appdata_sweep = include_appdata_sweep

    @Slot()
    def run(self):
        # all the heavy work happens here (off the UI thread)
        try:
            res = scan_system(
                progress=self._emit,
                include_tasks=self.include_tasks,
                include_processes=self.include_processes,
                include_services=self.include_services,
                include_appdata_sweep=self.include_appdata_sweep
            )
            self.finished.emit(res)
        except Exception as e:
            self.error.emit(str(e))

    def _emit(self, label, i, n):
        # detector calls back into here for step updates
        self.progress.emit(label, i, n)

# ------------------------------- Pretty Toggle -------------------------------
# Custom-styled QCheckBox to look like a modern toggle pill.
class PrettyToggle(QCheckBox):
    def __init__(self, text=""):
        super().__init__(text)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet("""
            QCheckBox { color:#cfcfcf; font-size:12px; border:none; }
            QCheckBox::indicator { width:44px; height:24px; border-radius:12px; background:#2a2a2d; border:none; }
            QCheckBox::indicator:checked   { background:#00b16a; border:none; }
        """)

# --------------------------------- Main App ----------------------------------
class KeyWatchApp(QWidget):
    def __init__(self):
        super().__init__()

        # Window basics
        self.setWindowTitle("KeyWatch 🧩")
        self.setFixedSize(400, 460)
        self.setStyleSheet("background: #161618;")  # base bg color (matches wrapper)

        # Wrapper frame with animated border (keeps neon effect around content)
        self.wrapper = QFrame(self)
        self.wrapper.setGeometry(0, 0, 400, 460)
        self.wrapper.setStyleSheet("background: #161618; border: 2px solid #ff00ff;")

        # Animate the border through the HSV wheel (subtle, continuous)
        self._border_hue = 0
        self._border_timer = QTimer(self)
        self._border_timer.timeout.connect(self._update_border_color)
        self._border_timer.start(30)  # smaller = faster color cycle

        # ---------- Header: title + status + step ----------
        title = QLabel("KeyWatch")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Segoe UI", 30, QFont.Bold))
        title.setStyleSheet("color:white; border:none;")

        self.status = QLabel("Ready to scan")
        self.status.setAlignment(Qt.AlignCenter)
        self.status.setFont(QFont("Segoe UI", 13))
        self.status.setStyleSheet("color:#b8b8bb; border:none;")

        self.step = QLabel("—")  # updated live: "Checking Startup …" → "Done"
        self.step.setAlignment(Qt.AlignCenter)
        self.step.setFont(QFont("Segoe UI", 11))
        self.step.setStyleSheet("color:#cfcfcf; border:none;")

        # ---------- Center “Status Card” (hero block) ----------
        # Headline + big state (“Safe / Warning / High Risk”) + tiny subline
        self.status_card = QFrame()
        self.status_card.setStyleSheet("background:#232326; border-radius:12px; border:none;")
        self.status_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        card_layout = QVBoxLayout(self.status_card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setAlignment(Qt.AlignCenter)

        self.card_headline = QLabel("Status")
        self.card_headline.setFont(QFont("Segoe UI", 13, QFont.Bold))
        self.card_headline.setAlignment(Qt.AlignCenter)
        self.card_headline.setStyleSheet("color:#b8b8bb;")

        self.card_state = QLabel("—")  # gets colored + text set on finish
        self.card_state.setFont(QFont("Segoe UI", 22, QFont.Bold))
        self.card_state.setAlignment(Qt.AlignCenter)
        self.card_state.setStyleSheet("color:#00e57d;")

        self.card_last = QLabel("Last scan: —")  # updated on finish
        self.card_last.setFont(QFont("Segoe UI", 10))
        self.card_last.setAlignment(Qt.AlignCenter)
        self.card_last.setStyleSheet("color:#9fa0a4;")

        card_layout.addWidget(self.card_headline)
        card_layout.addWidget(self.card_state)
        card_layout.addWidget(self.card_last)

        # ---------- Progress bar ----------
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        self.progress.setStyleSheet(
            "QProgressBar { background:#232326; border:none; } "
            "QProgressBar::chunk { background:#00b16a; border:none; }"
        )

        # ---------- Findings count + Deep scan toggle ----------
        self.findings = QLabel("Findings: 0")
        self.findings.setAlignment(Qt.AlignCenter)
        self.findings.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.findings.setStyleSheet("color:#00e57d; border:none;")

        self.deep = PrettyToggle("Deep scan")
        self.deep.setFont(QFont("Segoe UI", 13, QFont.Bold))
        # theme the label too (toggle visuals come from PrettyToggle)
        self.deep.setStyleSheet(
            "QCheckBox { color:#00e57d; font-size:15px; font-weight:bold; border:none; } "
            "QCheckBox::indicator { width:44px; height:24px; border-radius:12px; background:#2a2a2d; border:none; } "
            "QCheckBox::indicator:checked   { background:#00b16a; border:none; }"
        )

        # place findings + toggle on one centered row
        findings_row = QHBoxLayout()
        findings_row.setContentsMargins(0, 0, 0, 0)
        findings_row.setAlignment(Qt.AlignCenter)
        findings_row.addWidget(self.findings)
        findings_row.addWidget(self.deep)

        # ---------- Details modal trigger (secondary action) ----------
        self.details_btn = QPushButton("View details")
        self.details_btn.setCursor(Qt.PointingHandCursor)
        self.details_btn.setStyleSheet(
            "QPushButton { background:#232326; color:#00e57d; border-radius:8px; padding:6px 18px; font-size:13px; font-weight:bold; } "
            "QPushButton:hover { background:#333; color:#00e57d; }"
        )
        self.details_btn.clicked.connect(self.show_details_modal)

        # ---------- Primary CTA: Scan button ----------
        self.scan = QPushButton("Scan System")
        self.scan.setFixedHeight(48)
        self.scan.setMinimumWidth(0)
        self.scan.setMaximumWidth(400)
        self.scan.setFont(QFont("Segoe UI", 15, QFont.Bold))
        self.scan.setCursor(Qt.PointingHandCursor)
        self.scan.setStyleSheet(
            "QPushButton { background:#00b16a; color:white; border:none; } "
            "QPushButton:hover { background:#00e57d; border:none; } "
            "QPushButton:pressed { background:#008d56; border:none; }"
        )
        self.scan.clicked.connect(self.start_scan)

        # Soft glow around the scan button (kept as attribute so animation has a target)
        self.glow = QGraphicsDropShadowEffect()
        self.glow.setBlurRadius(26)
        self.glow.setColor(QColor("#00b16a"))
        self.glow.setOffset(0)
        self.scan.setGraphicsEffect(self.glow)

        # Glow pulse anim while scanning (green → amber loop)
        self.anim = QPropertyAnimation(self.glow, b"color")
        self.anim.setDuration(1200)
        self.anim.setLoopCount(-1)
        self.anim.setEasingCurve(QEasingCurve.InOutQuad)
        self.anim.setStartValue(QColor("#00b16a"))
        self.anim.setEndValue(QColor("#ffcc00"))

        # ------------------------------ Layout ------------------------------
        # Everything gets added to the wrapper’s layout (so the neon border frames it).
        lay = QVBoxLayout(self.wrapper)
        lay.setAlignment(Qt.AlignTop)
        lay.setContentsMargins(18, 16, 18, 16)

        # Top section
        lay.addWidget(title); lay.addSpacing(6)
        lay.addWidget(self.status)
        lay.addWidget(self.step)

        # Center hero card
        lay.addWidget(self.status_card)
        lay.addSpacing(8)

        # Progress + info row + details
        lay.addWidget(self.progress)
        lay.addLayout(findings_row)
        lay.addWidget(self.details_btn, alignment=Qt.AlignHCenter)

        # Push primary button to bottom while keeping nice spacing
        lay.addStretch(1)
        self.scan.setMinimumWidth(0)
        self.scan.setMaximumWidth(16777215)
        lay.addWidget(self.scan)
        lay.addSpacing(8)

        # runtime state
        self.thread = None
        self.worker = None
        self.last = None  # cached last scan result (used by details modal)

    # Animated neon border: increment hue and repaint frame border color
    def _update_border_color(self):
        self._border_hue = (self._border_hue + 2) % 360
        color = QColor.fromHsv(self._border_hue, 255, 255).name()
        # Only update the border of the frame, not any child widgets
        self.wrapper.setStyleSheet(f"background: #161618; border: 2px solid {color};")

    # ------------------------------ Scan Flow ------------------------------
    @Slot()
    def start_scan(self):
        # Prime UI for a new run
        self.status.setText("🔍 Scanning system…")
        self.status.setStyleSheet("color:#ffcc00;")
        self.step.setText("Starting…")
        self.progress.setValue(0)
        self.findings.setText("Findings: 0")

        # lock button + start pulse
        self.scan.setEnabled(False)
        self.anim.start()

        # Build worker with flags based on toggle
        deep = self.deep.isChecked()
        self.thread = QThread(self)
        self.worker = ScannerWorker(
            include_tasks=deep,
            include_processes=deep,
            include_services=deep,
            include_appdata_sweep=deep
        )
        self.worker.moveToThread(self.thread)

        # Wire signals
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)

        # Cleanup thread when done (no leaks)
        self.worker.finished.connect(self.thread.quit)
        self.worker.error.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(lambda: setattr(self, "thread", None))

        # Go
        self.thread.start()

    @Slot(str, int, int)
    def on_progress(self, label, i, n):
        # Update current step label + progress % safely on UI thread
        self.step.setText(label)
        self.progress.setValue(max(5, int(i / max(n, 1) * 100)))

    # ------------------------------ Details Modal ------------------------------
    # Minimal modal: table of findings (Kind/Reason/Path), read-only
    def show_details_modal(self):
        findings = self.last.get("findings", []) if self.last else []

        dlg = QDialog(self)
        dlg.setWindowTitle("Scan Findings")
        dlg.setFixedSize(360, 340)

        table = QTableWidget(dlg)
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Kind", "Reason", "Path"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setRowCount(len(findings))

        for i, x in enumerate(findings):
            table.setItem(i, 0, QTableWidgetItem(str(x.get("kind", ""))))
            table.setItem(i, 1, QTableWidgetItem(str(x.get("reason", ""))))
            table.setItem(i, 2, QTableWidgetItem(str(x.get("path", ""))))

        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        # simple manual geometry (good enough for a small modal)
        table.setGeometry(10, 10, 340, 260)

        btns = QDialogButtonBox(QDialogButtonBox.Ok, dlg)
        btns.setGeometry(120, 280, 120, 32)
        btns.accepted.connect(dlg.accept)

        dlg.exec()

    # ------------------------------ Finish/Error ------------------------------
    @Slot(dict)
    def on_finished(self, res):
        # Cache last result for modal
        self.last = res

        # Stop pulse + re-enable button + complete progress
        self.anim.stop()
        self.scan.setEnabled(True)
        self.progress.setValue(100)
        self.step.setText("Done")

        # Update quick counters + risk theme
        f = res.get("findings", [])
        self.findings.setText(f"Findings: {len(f)}")
        risk = res.get("risk", "warn")

        # Status card: headline stays “Status”, state + color change by risk
        self.card_headline.setText("Status")
        if risk == "safe":
            self.card_state.setText("✅ Safe")
            self.card_state.setStyleSheet("color:#00e57d;")
        elif risk == "warn":
            self.card_state.setText("⚠️ Warning")
            self.card_state.setStyleSheet("color:#ffcc00;")
        else:
            self.card_state.setText("🚨 High Risk")
            self.card_state.setStyleSheet("color:#ff4f4f;")

        # Subline: quick summary (score + count). (Could swap to timestamp if preferred.)
        self.card_last.setText(f"Last scan: {res.get('score', 0)} items, {len(f)} findings")

        # Header status + button color theme swap
        if risk == "safe":
            self.status.setText("✅ All clear! No obvious persistence found.")
            self.status.setStyleSheet("color:#00e57d;")
            self.scan.setStyleSheet(
                "QPushButton{background:#00b16a;color:white;border:none;}"
                "QPushButton:hover{background:#00e57d;border:none;}"
                "QPushButton:pressed{background:#008d56;border:none;}"
            )
        elif risk == "warn":
            self.status.setText("⚠️ Suspicious items found. Review recommended.")
            self.status.setStyleSheet("color:#ffcc00;")
            self.scan.setStyleSheet(
                "QPushButton{background:#ffcc00;color:black;border:none;}"
                "QPushButton:hover{background:#ffe680;border:none;}"
                "QPushButton:pressed{background:#e6b800;border:none;}"
            )
        else:
            self.status.setText("🚨 High risk: likely keylogger/persistence.")
            self.status.setStyleSheet("color:#ff4f4f;")
            self.scan.setStyleSheet(
                "QPushButton{background:#ff4f4f;color:white;border:none;}"
                "QPushButton:hover{background:#ff6666;border:none;}"
                "QPushButton:pressed{background:#cc3e3e;border:none;}"
            )

        # Console dump (handy while developing)
        print(f"\n--- Scan [{risk}] score={res.get('score',0)} items={len(f)} ---")
        for x in f:
            print(f"- [{x['kind']}] {x['reason']} :: {x['path']}")

    @Slot(str)
    def on_error(self, msg):
        # Reset UI gracefully if the worker bails
        self.anim.stop()
        self.scan.setEnabled(True)
        self.progress.setValue(0)
        self.status.setText("⚠️ Scan failed")
        self.status.setStyleSheet("color:#ffcc00;")
        print("Scan error:", msg)

# ---------------------------------- Boot -------------------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = KeyWatchApp()
    w.show()
    sys.exit(app.exec())
