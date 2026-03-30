"""Main application window — Modern redesigned GUI."""
from __future__ import annotations
import os
import csv
import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QFileDialog,
    QSplitter, QStatusBar, QMessageBox, QToolBar,
    QAction, QTextEdit, QFrame, QSizePolicy,
    QGraphicsDropShadowEffect,
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QTimer, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QColor, QFont, QPalette, QLinearGradient, QGradient

from ids.sniffer import PacketSniffer, list_interfaces
from ids.feature_extractor import extract_features
from ids.classifier import PacketClassifier
from ids.utils import logger, MODELS_DIR, get_model_files

from gui.packet_table import PacketTable
from gui.stats_panel import StatsPanel

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
except ImportError:
    IP = TCP = UDP = ICMP = None


# ── Color palette ─────────────────────────────────────────────────────────────
COLOR = {
    "bg":           "#0d1117",
    "surface":      "#161b22",
    "surface2":     "#1c2230",
    "border":       "#30363d",
    "border_accent":"#00d4aa",
    "text":         "#e6edf3",
    "text_muted":   "#8b949e",
    "text_faint":   "#484f58",
    "primary":      "#00d4aa",
    "primary_dim":  "#009e7e",
    "danger":       "#f85149",
    "danger_dim":   "#b91c1c",
    "warning":      "#e3b341",
    "success":      "#3fb950",
    "blue":         "#58a6ff",
}


class PacketSignal(QObject):
    new_packet = pyqtSignal(dict)


# ── Re-usable styled widgets ───────────────────────────────────────────────────

class PillButton(QPushButton):
    """Rounded pill-shaped button with colour variants."""
    STYLES = {
        "primary": (
            f"background:{COLOR['primary']};color:#0d1117;"
            f"border:none;border-radius:20px;padding:8px 22px;"
            f"font-weight:700;font-size:13px;"
        ),
        "danger": (
            f"background:{COLOR['danger']};color:#fff;"
            f"border:none;border-radius:20px;padding:8px 22px;"
            f"font-weight:700;font-size:13px;"
        ),
        "ghost": (
            f"background:transparent;color:{COLOR['text_muted']};"
            f"border:1px solid {COLOR['border']};border-radius:20px;"
            f"padding:8px 22px;font-size:13px;"
        ),
    }
    HOVER = {
        "primary": f"background:{COLOR['primary_dim']};color:#0d1117;",
        "danger":  f"background:{COLOR['danger_dim']};color:#fff;",
        "ghost":   f"background:{COLOR['surface2']};color:{COLOR['text']};",
    }

    def __init__(self, text: str, variant: str = "primary", parent=None):
        super().__init__(text, parent)
        self._variant = variant
        self._apply(self.STYLES[variant])
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(38)

    def _apply(self, css: str):
        self.setStyleSheet(css + "border-radius:20px;" if "border-radius" not in css else css)

    def enterEvent(self, event):
        base = self.STYLES[self._variant]
        self.setStyleSheet(base + f"background:{self.HOVER[self._variant].split(';')[0].split(':')[1]};")
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setStyleSheet(self.STYLES[self._variant])
        super().leaveEvent(event)


class SectionLabel(QLabel):
    """Small uppercase category label."""
    def __init__(self, text: str, parent=None):
        super().__init__(text.upper(), parent)
        self.setStyleSheet(
            f"color:{COLOR['text_faint']};font-size:10px;"
            f"font-weight:700;letter-spacing:1.5px;margin-bottom:2px;"
        )


class StyledCombo(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QComboBox {{
                background:{COLOR['surface2']};
                color:{COLOR['text']};
                border:1px solid {COLOR['border']};
                border-radius:8px;
                padding:6px 12px;
                font-size:13px;
                min-width:160px;
            }}
            QComboBox:hover {{ border-color:{COLOR['primary']}; }}
            QComboBox::drop-down {{ border:none; width:28px; }}
            QComboBox::down-arrow {{
                width:12px; height:12px;
                image: none;
                border-left:4px solid transparent;
                border-right:4px solid transparent;
                border-top:5px solid {COLOR['text_muted']};
            }}
            QComboBox QAbstractItemView {{
                background:{COLOR['surface2']};
                color:{COLOR['text']};
                selection-background-color:{COLOR['primary_dim']};
                border:1px solid {COLOR['border']};
                border-radius:8px;
                padding:4px;
            }}
        """)


class StatusDot(QLabel):
    """Animated pulsing status indicator."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(10, 10)
        self._active = False
        self._on = False
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._blink)
        self._set_color(COLOR['text_faint'])

    def set_active(self, active: bool):
        self._active = active
        if active:
            self._timer.start(600)
        else:
            self._timer.stop()
            self._set_color(COLOR['text_faint'])

    def _blink(self):
        self._on = not self._on
        self._set_color(COLOR['primary'] if self._on else COLOR['primary_dim'])

    def _set_color(self, color: str):
        self.setStyleSheet(
            f"background:{color};border-radius:5px;"
            f"box-shadow: 0 0 6px {color};"
        )


# ── Main Window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDS — Intrusion Detection System")
        self.setMinimumSize(1200, 760)
        self._sniffer: PacketSniffer | None = None
        self._classifier = PacketClassifier()
        self._signal = PacketSignal()
        self._signal.new_packet.connect(self._on_packet)
        self._packet_buffer: list[dict] = []
        self._is_running = False
        self._apply_global_style()
        self._build_ui()
        self._populate_interfaces()
        self._populate_models()

    # ── Global stylesheet ──────────────────────────────────────────────────────
    def _apply_global_style(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background:{COLOR['bg']};
                color:{COLOR['text']};
                font-family:'Segoe UI','SF Pro Display','Helvetica Neue',sans-serif;
                font-size:13px;
            }}
            QScrollBar:vertical {{
                background:{COLOR['surface']}; width:8px; border-radius:4px;
            }}
            QScrollBar::handle:vertical {{
                background:{COLOR['border']}; border-radius:4px; min-height:30px;
            }}
            QScrollBar::handle:vertical:hover {{ background:{COLOR['primary_dim']}; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}
            QScrollBar:horizontal {{
                background:{COLOR['surface']}; height:8px; border-radius:4px;
            }}
            QScrollBar::handle:horizontal {{
                background:{COLOR['border']}; border-radius:4px;
            }}
            QToolTip {{
                background:{COLOR['surface2']};
                color:{COLOR['text']};
                border:1px solid {COLOR['border']};
                border-radius:6px; padding:4px 8px;
            }}
            QSplitter::handle {{ background:{COLOR['border']}; width:1px; }}
            QStatusBar {{
                background:{COLOR['surface']};
                color:{COLOR['text_muted']};
                border-top:1px solid {COLOR['border']};
                font-size:12px; padding:2px 12px;
            }}
            QMessageBox {{
                background:{COLOR['surface']};
                color:{COLOR['text']};
            }}
        """)

    # ── Build UI ───────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Top header bar ─────────────────────────────────────────────────────
        header = QWidget()
        header.setFixedHeight(56)
        header.setStyleSheet(
            f"background:{COLOR['surface']};"
            f"border-bottom:1px solid {COLOR['border']};"
        )
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(20, 0, 20, 0)

        # Logo + title
        logo_lbl = QLabel()
        logo_lbl.setText(
            '<span style="font-size:22px;">🛡️</span>'
            f' <span style="color:{COLOR["text"]};font-size:16px;font-weight:700;">IDS</span>'
            f' <span style="color:{COLOR["text_muted"]};font-size:13px;">Intrusion Detection System</span>'
        )
        h_layout.addWidget(logo_lbl)
        h_layout.addStretch()

        # Status indicator
        self._status_dot = StatusDot()
        self._status_text = QLabel("Idle")
        self._status_text.setStyleSheet(f"color:{COLOR['text_muted']};font-size:12px;")
        dot_wrap = QHBoxLayout()
        dot_wrap.setSpacing(6)
        dot_wrap.addWidget(self._status_dot)
        dot_wrap.addWidget(self._status_text)
        h_layout.addLayout(dot_wrap)
        h_layout.addSpacing(24)

        # Header action buttons
        self._btn_export = PillButton("⬇  Export CSV", "ghost")
        self._btn_export.setToolTip("Export captured packets to CSV")
        self._btn_export.clicked.connect(self._export_csv)
        h_layout.addWidget(self._btn_export)
        h_layout.addSpacing(8)

        self._btn_clear = PillButton("✕  Clear", "ghost")
        self._btn_clear.setToolTip("Clear all captured packets")
        self._btn_clear.clicked.connect(self._clear)
        h_layout.addWidget(self._btn_clear)

        # ── Control bar ────────────────────────────────────────────────────────
        ctrl_bar = QWidget()
        ctrl_bar.setFixedHeight(64)
        ctrl_bar.setStyleSheet(
            f"background:{COLOR['surface2']};"
            f"border-bottom:1px solid {COLOR['border']};"
        )
        c_layout = QHBoxLayout(ctrl_bar)
        c_layout.setContentsMargins(20, 0, 20, 0)
        c_layout.setSpacing(20)

        # Interface selector
        iface_wrap = QVBoxLayout()
        iface_wrap.setSpacing(2)
        iface_wrap.addWidget(SectionLabel("Network Interface"))
        self._cmb_iface = StyledCombo()
        self._cmb_iface.setMinimumWidth(200)
        iface_wrap.addWidget(self._cmb_iface)
        c_layout.addLayout(iface_wrap)

        # Separator
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.VLine)
        sep1.setStyleSheet(f"color:{COLOR['border']};")
        c_layout.addWidget(sep1)

        # Model selector
        model_wrap = QVBoxLayout()
        model_wrap.setSpacing(2)
        model_wrap.addWidget(SectionLabel("Detection Model"))
        model_row = QHBoxLayout()
        model_row.setSpacing(8)
        self._cmb_model = StyledCombo()
        self._cmb_model.setMinimumWidth(220)
        self._cmb_model.currentIndexChanged.connect(self._on_model_changed)
        model_row.addWidget(self._cmb_model)
        self._lbl_model_status = QLabel("⚡ Demo")
        self._lbl_model_status.setStyleSheet(
            f"color:{COLOR['warning']};font-size:11px;font-weight:600;"
            f"background:{COLOR['surface']};border:1px solid {COLOR['warning']};"
            f"border-radius:10px;padding:2px 8px;"
        )
        model_row.addWidget(self._lbl_model_status)
        model_wrap.addLayout(model_row)
        c_layout.addLayout(model_wrap)

        c_layout.addStretch()

        # Start / Stop
        self._btn_start = PillButton("▶  Start Capture", "primary")
        self._btn_start.setFixedWidth(160)
        self._btn_start.clicked.connect(self._start_capture)
        c_layout.addWidget(self._btn_start)

        self._btn_stop = PillButton("⏹  Stop", "danger")
        self._btn_stop.setFixedWidth(120)
        self._btn_stop.setEnabled(False)
        self._btn_stop.clicked.connect(self._stop_capture)
        c_layout.addWidget(self._btn_stop)

        # ── KPI strip ──────────────────────────────────────────────────────────
        kpi_strip = QWidget()
        kpi_strip.setFixedHeight(76)
        kpi_strip.setStyleSheet(f"background:{COLOR['bg']};border-bottom:1px solid {COLOR['border']};")
        k_layout = QHBoxLayout(kpi_strip)
        k_layout.setContentsMargins(20, 8, 20, 8)
        k_layout.setSpacing(1)

        self._kpi_total    = self._make_kpi("TOTAL PACKETS",  "0",  COLOR['blue'])
        self._kpi_normal   = self._make_kpi("NORMAL",          "0",  COLOR['success'])
        self._kpi_malicious= self._make_kpi("MALICIOUS",       "0",  COLOR['danger'])
        self._kpi_rate     = self._make_kpi("THREAT RATIO",    "0%", COLOR['warning'])
        for kpi in [self._kpi_total, self._kpi_normal, self._kpi_malicious, self._kpi_rate]:
            k_layout.addWidget(kpi)
            if kpi is not self._kpi_rate:
                div = QFrame()
                div.setFrameShape(QFrame.VLine)
                div.setStyleSheet(f"color:{COLOR['border']};margin:4px 0;")
                k_layout.addWidget(div)

        # ── Main content area ──────────────────────────────────────────────────
        content = QWidget()
        c2_layout = QHBoxLayout(content)
        c2_layout.setContentsMargins(0, 0, 0, 0)
        c2_layout.setSpacing(0)

        # Packet table (main area)
        table_wrap = QWidget()
        table_layout = QVBoxLayout(table_wrap)
        table_layout.setContentsMargins(16, 12, 8, 12)
        table_layout.setSpacing(8)

        tbl_header = QHBoxLayout()
        tbl_title = QLabel("Live Packet Feed")
        tbl_title.setStyleSheet(
            f"color:{COLOR['text']};font-size:14px;font-weight:600;"
        )
        tbl_header.addWidget(tbl_title)
        tbl_header.addStretch()
        self._lbl_packet_count = QLabel("0 packets")
        self._lbl_packet_count.setStyleSheet(f"color:{COLOR['text_muted']};font-size:12px;")
        tbl_header.addWidget(self._lbl_packet_count)
        table_layout.addLayout(tbl_header)

        self._table = PacketTable()
        table_layout.addWidget(self._table)
        c2_layout.addWidget(table_wrap, stretch=3)

        # Right sidebar
        sidebar = QWidget()
        sidebar.setFixedWidth(320)
        sidebar.setStyleSheet(
            f"background:{COLOR['surface']};"
            f"border-left:1px solid {COLOR['border']};"
        )
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(16, 16, 16, 16)
        sb_layout.setSpacing(16)

        # Stats panel
        self._stats = StatsPanel()
        sb_layout.addWidget(self._stats)

        # Divider
        div2 = QFrame()
        div2.setFrameShape(QFrame.HLine)
        div2.setStyleSheet(f"color:{COLOR['border']};")
        sb_layout.addWidget(div2)

        # Alert log
        alert_title = QLabel("🚨  Alert Log")
        alert_title.setStyleSheet(
            f"color:{COLOR['danger']};font-size:13px;font-weight:700;"
        )
        sb_layout.addWidget(alert_title)

        self._alert_log = QTextEdit()
        self._alert_log.setReadOnly(True)
        self._alert_log.setStyleSheet(f"""
            QTextEdit {{
                background:{COLOR['bg']};
                color:{COLOR['danger']};
                font-family:'Cascadia Code','Fira Code','Consolas',monospace;
                font-size:11px;
                border:1px solid {COLOR['border']};
                border-radius:8px;
                padding:8px;
            }}
        """)
        sb_layout.addWidget(self._alert_log)
        c2_layout.addWidget(sidebar)

        # ── Assemble root layout ───────────────────────────────────────────────
        root_container = QWidget()
        root_layout = QVBoxLayout(root_container)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        root_layout.addWidget(header)
        root_layout.addWidget(ctrl_bar)
        root_layout.addWidget(kpi_strip)
        root_layout.addWidget(content, stretch=1)

        self.setCentralWidget(root_container)

        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)
        self._status_bar.showMessage("Ready  ·  Select a network interface and click Start Capture")

    # ── KPI card factory ───────────────────────────────────────────────────────
    def _make_kpi(self, label: str, value: str, accent: str) -> QWidget:
        card = QWidget()
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 6, 20, 6)
        layout.setSpacing(2)

        lbl = QLabel(label)
        lbl.setStyleSheet(
            f"color:{COLOR['text_faint']};font-size:9px;"
            f"font-weight:700;letter-spacing:1.4px;"
        )
        val = QLabel(value)
        val.setStyleSheet(
            f"color:{accent};font-size:26px;font-weight:800;"
            "font-variant-numeric:tabular-nums;"
        )
        layout.addWidget(lbl)
        layout.addWidget(val)
        card._value_lbl = val
        card._accent = accent
        return card

    def _update_kpi(self, card: QWidget, value: str):
        card._value_lbl.setText(value)

    # ── Interface / model population ───────────────────────────────────────────
    def _populate_interfaces(self):
        interfaces = list_interfaces()
        self._cmb_iface.addItems(interfaces if interfaces else ["No interfaces found"])

    def _populate_models(self):
        self._cmb_model.clear()
        self._cmb_model.addItem("⚡  Demo (rule-based)", None)
        for f in get_model_files():
            self._cmb_model.addItem(f"  {f}", os.path.join(MODELS_DIR, f))

    # ── Capture control ────────────────────────────────────────────────────────
    def _start_capture(self):
        iface = self._cmb_iface.currentText()
        if not iface or iface == "No interfaces found":
            self._show_error("No Interface", "Please select a valid network interface.")
            return
        self._sniffer = PacketSniffer(
            interface=iface,
            callback=lambda pkt: self._signal.new_packet.emit(self._parse_packet(pkt)),
        )
        self._sniffer.start()
        self._is_running = True
        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._status_dot.set_active(True)
        self._status_text.setText(f"Capturing on {iface}")
        self._status_text.setStyleSheet(f"color:{COLOR['primary']};font-size:12px;font-weight:600;")
        self._status_bar.showMessage(f"🔴  Live  ·  Capturing on {iface}")

    def _stop_capture(self):
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
        self._is_running = False
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._status_dot.set_active(False)
        self._status_text.setText("Idle")
        self._status_text.setStyleSheet(f"color:{COLOR['text_muted']};font-size:12px;")
        total = len(self._packet_buffer)
        mal = sum(1 for p in self._packet_buffer if p["label"] == "Malicious")
        self._status_bar.showMessage(
            f"Stopped  ·  Captured {total} packets  ·  {mal} malicious  ·  {total - mal} normal"
        )

    # ── Packet parsing ─────────────────────────────────────────────────────────
    def _parse_packet(self, pkt) -> dict:
        info = {
            "time":       datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src_ip":     "—",
            "dst_ip":     "—",
            "protocol":   "OTHER",
            "length":     len(pkt),
            "label":      "Normal",
            "confidence": 0.0,
        }
        try:
            if IP and pkt.haslayer("IP"):
                ip = pkt["IP"]
                info["src_ip"] = ip.src
                info["dst_ip"] = ip.dst
            if TCP and pkt.haslayer("TCP"):
                info["protocol"] = "TCP"
            elif UDP and pkt.haslayer("UDP"):
                info["protocol"] = "UDP"
            elif ICMP and pkt.haslayer("ICMP"):
                info["protocol"] = "ICMP"
            features = extract_features(pkt)
            if features is not None:
                result = self._classifier.predict(features)
                info["label"]      = result["label"]
                info["confidence"] = result["confidence"]
        except Exception as exc:
            logger.warning("Packet parse error: %s", exc)
        return info

    # ── Packet received ────────────────────────────────────────────────────────
    def _on_packet(self, info: dict):
        self._table.add_packet(
            info["time"], info["src_ip"], info["dst_ip"],
            info["protocol"], info["length"], info["label"], info["confidence"],
        )
        self._stats.update_stats(info["label"])
        self._packet_buffer.append(info)

        total = len(self._packet_buffer)
        mal   = sum(1 for p in self._packet_buffer if p["label"] == "Malicious")
        norm  = total - mal
        ratio = f"{mal / total:.0%}" if total else "0%"

        self._update_kpi(self._kpi_total,     str(total))
        self._update_kpi(self._kpi_normal,    str(norm))
        self._update_kpi(self._kpi_malicious, str(mal))
        self._update_kpi(self._kpi_rate,      ratio)
        self._lbl_packet_count.setText(f"{total:,} packets")

        if info["label"] == "Malicious":
            self._alert_log.append(
                f'<span style="color:{COLOR["danger"]};">[{info["time"]}]</span> '
                f'<span style="color:{COLOR["text"]};">{info["src_ip"]} → {info["dst_ip"]}'
                f' · {info["protocol"]} · {info["confidence"]:.1%} confidence</span>'
            )

        if total % 20 == 0:
            self._status_bar.showMessage(
                f"🔴  Live  ·  {total:,} packets  ·  {mal} malicious  ({ratio} threat ratio)"
            )

    # ── Model switch ───────────────────────────────────────────────────────────
    def _on_model_changed(self, index: int):
        path = self._cmb_model.itemData(index)
        if path is None:
            self._classifier = PacketClassifier()
            self._lbl_model_status.setText("⚡ Demo")
            self._lbl_model_status.setStyleSheet(
                f"color:{COLOR['warning']};font-size:11px;font-weight:600;"
                f"background:{COLOR['surface']};border:1px solid {COLOR['warning']};"
                f"border-radius:10px;padding:2px 8px;"
            )
        else:
            self._classifier = PacketClassifier(path)
            name = os.path.basename(path)
            self._lbl_model_status.setText(f"✓ {name}")
            self._lbl_model_status.setStyleSheet(
                f"color:{COLOR['success']};font-size:11px;font-weight:600;"
                f"background:{COLOR['surface']};border:1px solid {COLOR['success']};"
                f"border-radius:10px;padding:2px 8px;"
            )

    # ── Export / clear ─────────────────────────────────────────────────────────
    def _export_csv(self):
        if not self._packet_buffer:
            self._show_info("No Data", "Capture some packets first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save CSV", "ids_capture.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self._packet_buffer[0].keys())
            writer.writeheader()
            writer.writerows(self._packet_buffer)
        self._show_info("Exported", f"Saved {len(self._packet_buffer):,} packets to:\n{path}")

    def _clear(self):
        self._table.setRowCount(0)
        self._stats.reset()
        self._alert_log.clear()
        self._packet_buffer.clear()
        self._update_kpi(self._kpi_total,     "0")
        self._update_kpi(self._kpi_normal,    "0")
        self._update_kpi(self._kpi_malicious, "0")
        self._update_kpi(self._kpi_rate,      "0%")
        self._lbl_packet_count.setText("0 packets")
        self._status_bar.showMessage("Cleared.")

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _show_error(self, title: str, msg: str):
        dlg = QMessageBox(self)
        dlg.setWindowTitle(title)
        dlg.setText(msg)
        dlg.setIcon(QMessageBox.Warning)
        dlg.setStyleSheet(
            f"QMessageBox{{background:{COLOR['surface']};color:{COLOR['text']};}}"
            f"QPushButton{{background:{COLOR['primary']};color:#0d1117;"
            f"border:none;border-radius:8px;padding:6px 16px;font-weight:700;}}"
        )
        dlg.exec_()

    def _show_info(self, title: str, msg: str):
        dlg = QMessageBox(self)
        dlg.setWindowTitle(title)
        dlg.setText(msg)
        dlg.setIcon(QMessageBox.Information)
        dlg.setStyleSheet(
            f"QMessageBox{{background:{COLOR['surface']};color:{COLOR['text']};}}"
            f"QPushButton{{background:{COLOR['primary']};color:#0d1117;"
            f"border:none;border-radius:8px;padding:6px 16px;font-weight:700;}}"
        )
        dlg.exec_()

    def closeEvent(self, event):
        self._stop_capture()
        super().closeEvent(event)
