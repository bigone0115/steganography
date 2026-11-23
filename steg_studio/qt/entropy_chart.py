"""
구간별 엔트로피 차트 위젯 (QPainter 직접 렌더링).
"""

from PySide6.QtCore import Qt, QPointF
from PySide6.QtGui import QPainter, QPen, QColor, QFont
from PySide6.QtWidgets import QWidget

from .. import analysis
from . import theme


class EntropyChart(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumSize(460, 300)
        self._blocks = []
        self._total = 0
        self._natural_eof = 0

    def set_data(self, file_bytes, natural_eof):
        self._blocks = analysis.entropy_blocks(file_bytes)
        self._total = len(file_bytes)
        self._natural_eof = natural_eof
        self.update()

    def clear(self):
        self._blocks = []
        self._total = 0
        self._natural_eof = 0
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), QColor(theme.CRUST))

        w, h = self.width(), self.height()
        pad_l, pad_r, pad_t, pad_b = 48, 20, 24, 36
        plot_w = max(w - pad_l - pad_r, 100)
        plot_h = max(h - pad_t - pad_b, 100)

        small = QFont(theme.MONO, 8)
        p.setFont(small)

        # 가로 격자 + 눈금
        for val in (0, 2, 4, 6, 8):
            y = pad_t + plot_h - (val / 8.0) * plot_h
            p.setPen(QPen(QColor(theme.SURFACE0), 1, Qt.DashLine))
            p.drawLine(pad_l, int(y), pad_l + plot_w, int(y))
            p.setPen(QColor(theme.SUBTEXT))
            p.drawText(0, int(y) - 6, pad_l - 6, 12, Qt.AlignRight | Qt.AlignVCenter, f"{val}.0")

        if not self._blocks or not self._total:
            p.setPen(QColor(theme.SURFACE2))
            p.drawText(self.rect(), Qt.AlignCenter, "스캔하면 블록별 엔트로피 분포가 표시됩니다.")
            p.end()
            return

        # 7.5 임계선
        y_high = pad_t + plot_h - (7.5 / 8.0) * plot_h
        p.setPen(QPen(QColor(theme.RED), 1, Qt.DashLine))
        p.drawLine(pad_l, int(y_high), pad_l + plot_w, int(y_high))
        p.setPen(QColor(theme.RED))
        p.drawText(pad_l + 6, int(y_high) - 6, "7.5 (압축/암호화 임계선)")

        # 엔트로피 꺾은선
        n = len(self._blocks)
        pts = []
        for i, ent in enumerate(self._blocks):
            x = pad_l + (i / max(1, n - 1)) * plot_w
            y = pad_t + plot_h - (ent / 8.0) * plot_h
            pts.append(QPointF(x, y))
        p.setPen(QPen(QColor(theme.BLUE), 2))
        for i in range(1, len(pts)):
            p.drawLine(pts[i - 1], pts[i])

        # 정상 EOF 세로선
        if 0 < self._natural_eof < self._total:
            x_eof = pad_l + (self._natural_eof / self._total) * plot_w
            p.setPen(QPen(QColor(theme.YELLOW), 2, Qt.DashLine))
            p.drawLine(int(x_eof), pad_t, int(x_eof), pad_t + plot_h)
            p.setPen(QColor(theme.YELLOW))
            p.drawText(int(x_eof) + 4, pad_t + 12, f"Expected EOF (0x{self._natural_eof:X})")

        p.setPen(QColor(theme.SUBTEXT))
        p.drawText(pad_l, h - 10, "0x0 (파일 시작)")
        p.drawText(pad_l + plot_w - 120, h - 10, f"0x{self._total:X} (파일 끝)")
        p.end()
