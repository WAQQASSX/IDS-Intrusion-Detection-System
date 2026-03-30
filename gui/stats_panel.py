"""Modern statistics panel widget."""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar, QFrame,
)
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QColor

COLOR = {
    "bg":          "#0d1117",
    "surface":     "#161b22",
    "surface2":    "#1c2230",
    "border":      "#30363d",
    "text":        "#e6edf3",
    "text_muted":  "#8b949e",
    "text_faint":  "#484f58",
    "primary":     "#00d4aa",
    "danger":      "#f85149",
    "success":     "#3fb950",
    "warning":     "#e3b341",
    "blue":        "#58a6ff",
}


class MiniStatRow(QWidget):
    """A labelled value row with animated progress bar."""
    def __init__(self, label: str, accent: str, parent=None):
        super().__init__(parent)
        self._accent = accent
        self._total  = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        lbl = QLabel(label)
        lbl.setStyleSheet(
            f"color:{COLOR['text_muted']};font-size:11px;"
        )
        self._val_lbl = QLabel("0")
        self._val_lbl.setStyleSheet(
            f"color:{accent};font-size:18px;font-weight:800;"
            "font-variant-numeric:tabular-nums;"
        )
        top.addWidget(lbl)
        top.addStretch()
        top.addWidget(self._val_lbl)
        layout.addLayout(top)

        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(4)
        self._bar.setStyleSheet(f"""
            QProgressBar {{
                background:{COLOR['surface2']};
                border-radius:2px;
                border:none;
            }}
            QProgressBar::chunk {{
                background:{accent};
                border-radius:2px;
            }}
        """)
        layout.addWidget(self._bar)

    def update(self, value: int, total: int):
        self._val_lbl.setText(str(value))
        pct = int((value / total * 100)) if total > 0 else 0
        self._bar.setValue(pct)


class StatsPanel(QWidget):
    """Sidebar statistics panel — protocol breakdown + detection counts."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._counts = {"Normal": 0, "Malicious": 0}
        self._proto  = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self._total  = 0
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Detection section header
        det_title = QLabel("DETECTION OVERVIEW")
        det_title.setStyleSheet(
            f"color:{COLOR['text_faint']};font-size:9px;"
            f"font-weight:700;letter-spacing:1.5px;"
        )
        layout.addWidget(det_title)

        self._row_normal = MiniStatRow("Normal traffic", COLOR["success"])
        layout.addWidget(self._row_normal)

        self._row_malicious = MiniStatRow("Malicious traffic", COLOR["danger"])
        layout.addWidget(self._row_malicious)

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.HLine)
        div.setStyleSheet(f"color:{COLOR['border']};margin:4px 0;")
        layout.addWidget(div)

        # Protocol section header
        proto_title = QLabel("PROTOCOL BREAKDOWN")
        proto_title.setStyleSheet(
            f"color:{COLOR['text_faint']};font-size:9px;"
            f"font-weight:700;letter-spacing:1.5px;"
        )
        layout.addWidget(proto_title)

        self._row_tcp   = MiniStatRow("TCP",   COLOR["blue"])
        self._row_udp   = MiniStatRow("UDP",   "#a86fdf")
        self._row_icmp  = MiniStatRow("ICMP",  COLOR["warning"])
        self._row_other = MiniStatRow("Other", COLOR["text_muted"])
        for row in [self._row_tcp, self._row_udp, self._row_icmp, self._row_other]:
            layout.addWidget(row)

        layout.addStretch()

    def update_stats(self, label: str, protocol: str = "OTHER"):
        self._total += 1
        self._counts[label] = self._counts.get(label, 0) + 1
        self._proto[protocol] = self._proto.get(protocol, 0) + 1

        self._row_normal.update(self._counts.get("Normal", 0),    self._total)
        self._row_malicious.update(self._counts.get("Malicious", 0), self._total)
        self._row_tcp.update(self._proto["TCP"],   self._total)
        self._row_udp.update(self._proto["UDP"],   self._total)
        self._row_icmp.update(self._proto["ICMP"],  self._total)
        self._row_other.update(self._proto["OTHER"], self._total)

    def reset(self):
        self._counts = {"Normal": 0, "Malicious": 0}
        self._proto  = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self._total  = 0
        for row in [
            self._row_normal, self._row_malicious,
            self._row_tcp, self._row_udp, self._row_icmp, self._row_other,
        ]:
            row.update(0, 0)
