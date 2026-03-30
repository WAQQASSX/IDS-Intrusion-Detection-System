"""Live packet table widget."""
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt
from ids.utils import LABEL_COLORS

COLUMNS = ["#", "Time", "Src IP", "Dst IP", "Protocol", "Length", "Label", "Confidence"]
MAX_ROWS = 500


class PacketTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(0, len(COLUMNS), parent)
        self.setHorizontalHeaderLabels(COLUMNS)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self._row_counter = 0

    def add_packet(self, time_str: str, src_ip: str, dst_ip: str,
                   protocol: str, length: int, label: str, confidence: float):
        self._row_counter += 1
        if self.rowCount() >= MAX_ROWS:
            self.removeRow(0)
        row = self.rowCount()
        self.insertRow(row)
        values = [
            str(self._row_counter), time_str, src_ip, dst_ip,
            protocol, str(length), label, f"{confidence:.1%}",
        ]
        color = QColor(LABEL_COLORS.get(0 if label == "Normal" else 1, "#ffffff"))
        color.setAlpha(40)
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignCenter)
            item.setBackground(color)
            self.setItem(row, col, item)
        self.scrollToBottom()
