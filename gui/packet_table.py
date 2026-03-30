"""Modern live packet table widget."""
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtCore import Qt
from ids.utils import LABEL_COLORS

COLUMNS = ["#", "Time", "Src IP", "Dst IP", "Protocol", "Length", "Label", "Confidence"]
COL_WIDTHS = [50, 110, 140, 140, 80, 70, 90, 90]
MAX_ROWS = 500

COLOR = {
    "bg":         "#0d1117",
    "surface":    "#161b22",
    "surface2":   "#1c2230",
    "border":     "#30363d",
    "text":       "#e6edf3",
    "text_muted": "#8b949e",
    "header_bg":  "#161b22",
    "row_alt":    "#12171e",
    "danger":     "#f85149",
    "danger_bg":  "#2a1215",
    "success":    "#3fb950",
    "success_bg": "#0f1f0f",
    "primary":    "#00d4aa",
    "warning":    "#e3b341",
    "blue":       "#58a6ff",
    "purple":     "#a86fdf",
}

PROTOCOL_COLORS = {
    "TCP":   COLOR["blue"],
    "UDP":   COLOR["purple"],
    "ICMP":  COLOR["warning"],
    "OTHER": COLOR["text_muted"],
}


class PacketTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(0, len(COLUMNS), parent)
        self._row_counter = 0
        self._setup_appearance()

    def _setup_appearance(self):
        self.setHorizontalHeaderLabels(COLUMNS)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setAlternatingRowColors(False)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)
        self.setFocusPolicy(Qt.NoFocus)
        self.setSortingEnabled(False)

        # Column widths
        hdr = self.horizontalHeader()
        hdr.setDefaultSectionSize(100)
        hdr.setHighlightSections(False)
        for i, w in enumerate(COL_WIDTHS):
            self.setColumnWidth(i, w)
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)

        self.setStyleSheet(f"""
            QTableWidget {{
                background:{COLOR['bg']};
                color:{COLOR['text']};
                border:1px solid {COLOR['border']};
                border-radius:8px;
                gridline-color:transparent;
                outline:none;
                font-size:12px;
            }}
            QTableWidget::item {{
                padding:6px 10px;
                border-bottom:1px solid {COLOR['border']};
            }}
            QTableWidget::item:selected {{
                background:{COLOR['surface2']};
                color:{COLOR['text']};
            }}
            QTableWidget::item:hover {{
                background:{COLOR['surface']};
            }}
            QHeaderView::section {{
                background:{COLOR['header_bg']};
                color:{COLOR['text_muted']};
                font-size:10px;
                font-weight:700;
                letter-spacing:1px;
                text-transform:uppercase;
                padding:8px 10px;
                border:none;
                border-bottom:1px solid {COLOR['border']};
            }}
            QHeaderView {{
                border-radius:8px 8px 0 0;
            }}
        """)
        self.setRowHeight(0, 36)
        self.verticalHeader().setDefaultSectionSize(36)

    def add_packet(
        self,
        time_str: str,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        length: int,
        label: str,
        confidence: float,
    ):
        self._row_counter += 1
        if self.rowCount() >= MAX_ROWS:
            self.removeRow(0)

        row = self.rowCount()
        self.insertRow(row)
        self.setRowHeight(row, 36)

        is_malicious = label == "Malicious"
        row_bg = QColor(COLOR["danger_bg"]) if is_malicious else (
            QColor(COLOR["row_alt"]) if row % 2 == 0 else QColor(COLOR["bg"])
        )

        proto_color = PROTOCOL_COLORS.get(protocol, COLOR["text_muted"])
        label_color = COLOR["danger"] if is_malicious else COLOR["success"]

        values = [
            str(self._row_counter),
            time_str,
            src_ip,
            dst_ip,
            protocol,
            str(length),
            label,
            f"{confidence:.1%}",
        ]

        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
            item.setBackground(row_bg)

            if col == 0:  # row number — faint
                item.setForeground(QColor(COLOR["text_muted"]))
            elif col == 4:  # protocol — colored
                item.setForeground(QColor(proto_color))
                f = item.font()
                f.setWeight(QFont.Bold)
                item.setFont(f)
            elif col == 6:  # label — colored + bold
                item.setForeground(QColor(label_color))
                f = item.font()
                f.setWeight(QFont.Bold)
                item.setFont(f)
            elif col == 7:  # confidence
                item.setForeground(
                    QColor(COLOR["danger"]) if is_malicious else QColor(COLOR["success"])
                )
            else:
                item.setForeground(QColor(COLOR["text"]))

            self.setItem(row, col, item)

        self.scrollToBottom()
