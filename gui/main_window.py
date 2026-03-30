"""Main application window."""
from __future__ import annotations
import os
import csv
import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QFileDialog,
    QSplitter, QStatusBar, QMessageBox, QToolBar,
    QAction, QGroupBox, QTextEdit,
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject

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


class PacketSignal(QObject):
    new_packet = pyqtSignal(dict)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ IDS – Intrusion Detection System")
        self.setMinimumSize(1100, 700)
        self._sniffer: PacketSniffer | None = None
        self._classifier = PacketClassifier()
        self._signal = PacketSignal()
        self._signal.new_packet.connect(self._on_packet)
        self._packet_buffer: list[dict] = []
        self._build_ui()
        self._populate_interfaces()
        self._populate_models()

    def _build_ui(self):
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)

        self._act_start = QAction("▶  Start Capture", self)
        self._act_start.triggered.connect(self._start_capture)
        toolbar.addAction(self._act_start)

        self._act_stop = QAction("⏹  Stop", self)
        self._act_stop.setEnabled(False)
        self._act_stop.triggered.connect(self._stop_capture)
        toolbar.addAction(self._act_stop)

        toolbar.addSeparator()
        self._act_export = QAction("💾  Export CSV", self)
        self._act_export.triggered.connect(self._export_csv)
        toolbar.addAction(self._act_export)

        self._act_clear = QAction("🗑  Clear", self)
        self._act_clear.triggered.connect(self._clear)
        toolbar.addAction(self._act_clear)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(8, 8, 8, 8)

        ctrl = QGroupBox("Configuration")
        ctrl_layout = QHBoxLayout(ctrl)
        ctrl_layout.addWidget(QLabel("Interface:"))
        self._cmb_iface = QComboBox()
        self._cmb_iface.setMinimumWidth(180)
        ctrl_layout.addWidget(self._cmb_iface)

        ctrl_layout.addWidget(QLabel("  Model:"))
        self._cmb_model = QComboBox()
        self._cmb_model.setMinimumWidth(200)
        self._cmb_model.currentIndexChanged.connect(self._on_model_changed)
        ctrl_layout.addWidget(self._cmb_model)

        self._lbl_model_status = QLabel("● Demo mode")
        self._lbl_model_status.setStyleSheet("color: #f39c12; font-weight: bold;")
        ctrl_layout.addWidget(self._lbl_model_status)
        ctrl_layout.addStretch()

        self._btn_start = QPushButton("▶  Start")
        self._btn_start.setStyleSheet("background:#27ae60;color:white;padding:6px 16px;border-radius:4px;")
        self._btn_start.clicked.connect(self._start_capture)
        ctrl_layout.addWidget(self._btn_start)

        self._btn_stop = QPushButton("⏹  Stop")
        self._btn_stop.setStyleSheet("background:#e74c3c;color:white;padding:6px 16px;border-radius:4px;")
        self._btn_stop.setEnabled(False)
        self._btn_stop.clicked.connect(self._stop_capture)
        ctrl_layout.addWidget(self._btn_stop)
        root.addWidget(ctrl)

        splitter = QSplitter(Qt.Horizontal)
        self._table = PacketTable()
        splitter.addWidget(self._table)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self._stats = StatsPanel()
        right_layout.addWidget(self._stats)

        alert_grp = QGroupBox("🚨 Alert Log")
        alert_layout = QVBoxLayout(alert_grp)
        self._alert_log = QTextEdit()
        self._alert_log.setReadOnly(True)
        self._alert_log.setMaximumHeight(200)
        self._alert_log.setStyleSheet(
            "background:#1e1e1e;color:#e74c3c;font-family:monospace;font-size:11px;"
        )
        alert_layout.addWidget(self._alert_log)
        right_layout.addWidget(alert_grp)
        splitter.addWidget(right)
        splitter.setSizes([750, 350])
        root.addWidget(splitter)

        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("Ready. Select an interface and click Start.")

        self.setStyleSheet("""
            QMainWindow { background: #2b2b2b; }
            QGroupBox { font-weight: bold; border: 1px solid #555; border-radius: 4px;
                        margin-top: 8px; padding-top: 8px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; color: #aaa; }
            QComboBox, QLabel { color: #ddd; }
            QTableWidget { background: #1e1e1e; color: #ddd; gridline-color: #3a3a3a; }
            QHeaderView::section { background: #3a3a3a; color: #ddd; padding: 4px; border: none; }
            QToolBar { background: #3a3a3a; border: none; spacing: 4px; }
            QToolButton { color: #ddd; padding: 4px 8px; }
            QToolButton:hover { background: #555; border-radius: 4px; }
            QStatusBar { background: #3a3a3a; color: #aaa; }
            QWidget { background: #2b2b2b; }
        """)

    def _populate_interfaces(self):
        interfaces = list_interfaces()
        self._cmb_iface.addItems(interfaces if interfaces else ["No interfaces found"])

    def _populate_models(self):
        self._cmb_model.clear()
        self._cmb_model.addItem("⚡ Demo (rule-based)", None)
        for f in get_model_files():
            self._cmb_model.addItem(f, os.path.join(MODELS_DIR, f))

    def _start_capture(self):
        iface = self._cmb_iface.currentText()
        if not iface or iface == "No interfaces found":
            QMessageBox.warning(self, "No Interface", "Please select a valid network interface.")
            return
        self._sniffer = PacketSniffer(
            interface=iface,
            callback=lambda pkt: self._signal.new_packet.emit(self._parse_packet(pkt)),
        )
        self._sniffer.start()
        self._btn_start.setEnabled(False)
        self._act_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._act_stop.setEnabled(True)
        self._status.showMessage(f"Capturing on {iface}…")

    def _stop_capture(self):
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
        self._btn_start.setEnabled(True)
        self._act_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._act_stop.setEnabled(False)
        self._status.showMessage("Capture stopped.")

    def _parse_packet(self, pkt) -> dict:
        info = {
            "time":       datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src_ip":     "?",
            "dst_ip":     "?",
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

    def _on_packet(self, info: dict):
        self._table.add_packet(
            info["time"], info["src_ip"], info["dst_ip"],
            info["protocol"], info["length"], info["label"], info["confidence"],
        )
        self._stats.update_stats(info["label"])
        self._packet_buffer.append(info)
        if info["label"] == "Malicious":
            msg = (
                f"[{info['time']}] ALERT: {info['src_ip']} → {info['dst_ip']} "
                f"({info['protocol']}) Conf: {info['confidence']:.1%}"
            )
            self._alert_log.append(msg)
        total = len(self._packet_buffer)
        if total % 10 == 0:
            mal = sum(1 for p in self._packet_buffer if p["label"] == "Malicious")
            self._status.showMessage(f"Captured: {total} | Malicious: {mal} | Normal: {total - mal}")

    def _on_model_changed(self, index: int):
        path = self._cmb_model.itemData(index)
        if path is None:
            self._classifier = PacketClassifier()
            self._lbl_model_status.setText("● Demo mode")
            self._lbl_model_status.setStyleSheet("color: #f39c12; font-weight: bold;")
        else:
            self._classifier = PacketClassifier(path)
            self._lbl_model_status.setText(f"✅ {os.path.basename(path)}")
            self._lbl_model_status.setStyleSheet("color: #27ae60; font-weight: bold;")

    def _export_csv(self):
        if not self._packet_buffer:
            QMessageBox.information(self, "No Data", "Capture some packets first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "ids_capture.csv", "CSV Files (*.csv)")
        if not path:
            return
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self._packet_buffer[0].keys())
            writer.writeheader()
            writer.writerows(self._packet_buffer)
        QMessageBox.information(self, "Exported", f"Saved {len(self._packet_buffer)} packets to:\n{path}")

    def _clear(self):
        self._table.setRowCount(0)
        self._stats.reset()
        self._alert_log.clear()
        self._packet_buffer.clear()
        self._status.showMessage("Cleared.")

    def closeEvent(self, event):
        self._stop_capture()
        super().closeEvent(event)
