"""
메타데이터 탭 (Qt) — 파일 열기 → 메타데이터 보기/편집 → 변경 저장 / 전체 삭제(스크럽) 저장.
이미지(JPEG/PNG)/PDF/Office(OOXML)/MP3/MP4 지원. 픽셀·본문은 보존하고 메타만 수정/제거.
"""
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, QLineEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog, QMessageBox, QAbstractItemView,
)

from .. import metaedit
from ..constants import MAX_SCAN_FILE_BYTES


class MetaTab(QWidget):
    def __init__(self):
        super().__init__()
        self._data = None
        self._path = None
        self._orig = {}      # key -> 원래 값
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        box = QGroupBox(" 메타데이터 편집 / 삭제 ")
        h = QHBoxLayout(box)
        h.addWidget(QLabel("파일:"))
        self.ed_path = QLineEdit()
        self.ed_path.setReadOnly(True)
        h.addWidget(self.ed_path, 1)
        btn_open = QPushButton("파일 열기")
        btn_open.clicked.connect(self._open)
        h.addWidget(btn_open)
        root.addWidget(box)

        self.lbl_fmt = QLabel("파일을 열면 메타데이터가 표시됩니다. 값 칸을 더블클릭해 편집하세요.")
        self.lbl_fmt.setObjectName("hint")
        root.addWidget(self.lbl_fmt)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["키", "값 (편집 가능)"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        root.addWidget(self.table, 1)

        self.lbl_alerts = QLabel("")
        self.lbl_alerts.setWordWrap(True)
        self.lbl_alerts.setStyleSheet("color: #e0a030;")
        self.lbl_alerts.setVisible(False)
        root.addWidget(self.lbl_alerts)

        ex = QHBoxLayout()
        self.btn_save = QPushButton("변경 저장")
        self.btn_save.setObjectName("accent")
        self.btn_save.clicked.connect(self._save_edits)
        self.btn_scrub = QPushButton("전체 삭제(스크럽) 저장")
        self.btn_scrub.clicked.connect(self._scrub)
        for b in (self.btn_save, self.btn_scrub):
            b.setEnabled(False)
            ex.addWidget(b)
        ex.addStretch(1)
        root.addLayout(ex)

        self.status = QLabel("")
        self.status.setObjectName("hint")
        root.addWidget(self.status)

    def _open(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "메타데이터를 편집할 파일 선택", "",
            "지원 파일 (*.jpg *.jpeg *.png *.webp *.tif *.tiff *.heic *.heif *.avif *.pdf *.docx *.xlsx *.pptx "
            "*.hwpx *.mp3 *.wav *.mp4 *.mov *.m4a);;모든 파일 (*.*)")
        if not path:
            return
        try:
            if os.path.getsize(path) > MAX_SCAN_FILE_BYTES:
                QMessageBox.warning(self, "크기 초과",
                                    f"파일이 안전 상한선({MAX_SCAN_FILE_BYTES:,} B)을 초과합니다.")
                return
            with open(path, "rb") as f:
                self._data = f.read()
        except Exception as e:
            QMessageBox.warning(self, "열기 실패", str(e))
            return
        self._path = path
        self.ed_path.setText(path)
        self._show()

    def _show(self):
        try:
            fmt, rows, alerts = metaedit.inspect(self._data)
        except Exception as e:
            self.lbl_fmt.setText(f"메타데이터 읽기 실패: {e}")
            return
        # 개인정보 노출·편집/조작 흔적 경보 (포렌식)
        self.lbl_alerts.setText("\n".join(f"⚠ {a}" for a in alerts))
        self.lbl_alerts.setVisible(bool(alerts))
        self._orig = {k: v for k, v in rows}
        self.lbl_fmt.setText(f"포맷: {fmt} · 메타데이터 {len(rows)}개 (값 칸 더블클릭 편집)")
        self.table.setRowCount(0)
        for k, v in rows:
            r = self.table.rowCount()
            self.table.insertRow(r)
            ki = QTableWidgetItem(k)
            ki.setFlags(ki.flags() & ~Qt.ItemIsEditable)   # 키는 읽기전용
            vi = QTableWidgetItem(v)                        # 값은 편집 가능
            self.table.setItem(r, 0, ki)
            self.table.setItem(r, 1, vi)
        can = bool(rows)
        self.btn_save.setEnabled(can)
        self.btn_scrub.setEnabled(self._data is not None)
        self.status.setText("")

    def _collect_changes(self):
        changes = {}
        for r in range(self.table.rowCount()):
            k = self.table.item(r, 0).text()
            v = self.table.item(r, 1).text()
            if v != self._orig.get(k):
                changes[k] = v
        return changes

    def _save_edits(self):
        changes = self._collect_changes()
        if not changes:
            self.status.setText("변경된 값이 없습니다.")
            return
        try:
            new, info = metaedit.edit(self._data, changes)
        except Exception as e:
            QMessageBox.warning(self, "편집 불가", str(e))
            return
        self._write(new, "_edited", info)

    def _scrub(self):
        if self._data is None:
            return
        if QMessageBox.question(self, "전체 삭제", "모든 메타데이터를 제거한 사본을 저장할까요?\n(픽셀·본문은 보존됩니다)") != QMessageBox.Yes:
            return
        try:
            new, info = metaedit.scrub(self._data)
        except Exception as e:
            QMessageBox.warning(self, "삭제 불가", str(e))
            return
        self._write(new, "_scrubbed", info)

    def _write(self, newbytes, suffix, info):
        base, ext = os.path.splitext(self._path)
        path, _ = QFileDialog.getSaveFileName(self, "저장", base + suffix + ext, "모든 파일 (*.*)")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(newbytes)
        except Exception as e:
            QMessageBox.warning(self, "저장 실패", str(e))
            return
        self.status.setText(f"저장 완료: {path}  ({info})")
