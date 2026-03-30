"""Statistics panel showing counters and threat ratio bar."""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGroupBox, QProgressBar
)
from PyQt5.QtCore import Qt


class StatsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._total     = 0
        self._normal    = 0
        self._malicious = 0
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        grp = QGroupBox("📊 Session Statistics")
        grp_layout = QVBoxLayout(grp)
        self._lbl_total     = self._counter_label("Total Packets", "0", "#2980b9")
        self._lbl_normal    = self._counter_label("Normal",        "0", "#27ae60")
        self._lbl_malicious = self._counter_label("Malicious",     "0", "#e74c3c")
        self._lbl_rate      = self._counter_label("Threat Rate",   "0%", "#8e44ad")
        for lbl in [self._lbl_total, self._lbl_normal, self._lbl_malicious, self._lbl_rate]:
            grp_layout.addWidget(lbl)
        layout.addWidget(grp)

        bar_grp = QGroupBox("🔴 Threat Ratio")
        bar_layout = QVBoxLayout(bar_grp)
        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setStyleSheet(
            "QProgressBar { border:1px solid #ccc; border-radius:4px; background:#ecf0f1; }"
            "QProgressBar::chunk { background:#e74c3c; border-radius:4px; }"
        )
        bar_layout.addWidget(self._bar)
        layout.addWidget(bar_grp)
        layout.addStretch()

    def update_stats(self, label: str):
        self._total += 1
        if label == "Normal":
            self._normal += 1
        else:
            self._malicious += 1
        rate = (self._malicious / self._total * 100) if self._total else 0
        self._lbl_total.findChild(QLabel, "value").setText(str(self._total))
        self._lbl_normal.findChild(QLabel, "value").setText(str(self._normal))
        self._lbl_malicious.findChild(QLabel, "value").setText(str(self._malicious))
        self._lbl_rate.findChild(QLabel, "value").setText(f"{rate:.1f}%")
        self._bar.setValue(int(rate))

    def reset(self):
        self._total = self._normal = self._malicious = 0
        for lbl in [self._lbl_total, self._lbl_normal, self._lbl_malicious, self._lbl_rate]:
            lbl.findChild(QLabel, "value").setText("0")
        self._bar.setValue(0)

    @staticmethod
    def _counter_label(title: str, value: str, color: str) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 2, 0, 2)
        lbl_title = QLabel(title + ":")
        lbl_title.setStyleSheet("font-weight: bold;")
        lbl_value = QLabel(value)
        lbl_value.setObjectName("value")
        lbl_value.setStyleSheet(f"color: {color}; font-size: 14px; font-weight: bold;")
        lbl_value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        h.addWidget(lbl_title)
        h.addStretch()
        h.addWidget(lbl_value)
        return w
