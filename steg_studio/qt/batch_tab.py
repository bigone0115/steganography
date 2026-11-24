"""
디렉터리 일괄 스캔 탭 (Qt).
헤더 클릭: 판정/포맷 = 값 필터, 파일명/크기 = 오름/내림 정렬, 탐지요약 = '특이사항 없음' 숨김 토글.
"""

import os

from PySide6.QtCore import Qt, Signal, QPoint
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, QLineEdit, QLabel,
    QCheckBox, QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QAbstractItemView, QMenu, QProgressBar,
)

from .workers import BatchWorker
from .. import engine

_HEADERS = ["#", "판정", "파일명", "포맷", "크기(B)", "탐지 요약"]
_COL_VERDICT, _COL_NAME, _COL_FMT, _COL_SIZE, _COL_SUMMARY = 1, 2, 3, 4, 5


class BatchTab(QWidget):
    open_in_scanner = Signal(str)   # 더블클릭한 파일 경로

    def __init__(self):
        super().__init__()
        self.worker = None
        self._files = []
        self._results = []
        self._rows = []             # 표시용 행 데이터(dict)
        self._sort_col = None       # _COL_NAME 또는 _COL_SIZE
        self._sort_desc = False
        self._filters = {}          # {col: 허용값} (판정/포맷)
        self._hide_clean = False
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        box = QGroupBox(" 디렉터리 일괄 보안 스캔 ")
        h = QHBoxLayout(box)
        h.addWidget(QLabel("대상 폴더:"))
        self.ed_dir = QLineEdit()
        h.addWidget(self.ed_dir, 1)
        b = QPushButton("폴더 선택")
        b.clicked.connect(self._pick_dir)
        h.addWidget(b)
        self.chk_recursive = QCheckBox("하위 폴더 포함")
        self.chk_recursive.setChecked(True)
        h.addWidget(self.chk_recursive)
        self.btn_run = QPushButton("일괄 스캔 시작")
        self.btn_run.setObjectName("accent")
        self.btn_run.clicked.connect(self._run)
        h.addWidget(self.btn_run)
        root.addWidget(box)

        self.status = QLabel("폴더를 선택하고 [일괄 스캔 시작]을 누르세요.")
        self.status.setObjectName("hint")
        root.addWidget(self.status)

        self.pbar = QProgressBar()
        self.pbar.setVisible(False)
        root.addWidget(self.pbar)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(_HEADERS)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(_COL_SUMMARY, QHeaderView.Stretch)
        for c in (0, _COL_VERDICT, _COL_NAME, _COL_FMT, _COL_SIZE):
            hh.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        hh.setSectionsClickable(True)
        hh.sectionClicked.connect(self._on_header)
        self.table.doubleClicked.connect(self._on_double_click)
        root.addWidget(self.table, 1)

        ex = QHBoxLayout()
        self.btn_csv = QPushButton("CSV 리포트 저장")
        self.btn_csv.clicked.connect(lambda: self._export("csv"))
        self.btn_html = QPushButton("HTML 리포트 저장")
        self.btn_html.clicked.connect(lambda: self._export("html"))
        for b in (self.btn_csv, self.btn_html):
            b.setEnabled(False)
            ex.addWidget(b)
        ex.addStretch(1)
        root.addLayout(ex)

        hint = QLabel("헤더 클릭 → 판정·포맷: 값 필터 / 파일명·크기: 오름·내림 정렬 / 탐지 요약: '특이사항 없음' 숨김.  "
                      "행 더블클릭 → 스캐너 탭에서 열기.")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        root.addWidget(hint)

    def _pick_dir(self):
        # XFCE 등에서 네이티브 폴더 대화상자가 선택이 안 먹는 경우가 있어 Qt 자체 대화상자로 강제(폴더 한 번 클릭 → Choose).
        start = self.ed_dir.text().strip() or os.path.expanduser("~")
        d = QFileDialog.getExistingDirectory(
            self, "일괄 스캔할 폴더 선택", start,
            QFileDialog.ShowDirsOnly | QFileDialog.DontUseNativeDialog)
        if d:
            self.ed_dir.setText(d)

    def _collect(self, folder):
        # CLI 배치와 동일하게 확장자로 거르지 않고 전부 수집 — 포맷 판별·분석은 엔진이 '내용'으로 한다.
        # (스테가 파일을 .unknown 등으로 위장해도 수집 단계에서 누락되지 않게)
        files = []
        if self.chk_recursive.isChecked():
            for dp, _, fns in os.walk(folder):
                files += [os.path.join(dp, fn) for fn in fns]
        else:
            for fn in os.listdir(folder):
                fp = os.path.join(folder, fn)
                if os.path.isfile(fp):
                    files.append(fp)
        return files

    def _run(self):
        # 스캔 중이면 '취소' 동작
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.status.setText("취소 중… (진행 중인 파일 끝나면 중단)")
            self.btn_run.setEnabled(False)
            return
        folder = self.ed_dir.text().strip()
        if not os.path.isdir(folder):
            self.status.setText("유효한 폴더를 선택하세요.")
            return
        files = self._collect(folder)
        if not files:
            self.status.setText("스캔할 파일이 없습니다.")
            return
        self.table.setRowCount(0)
        self._files = files
        self._results = []
        self._rows = []
        self._filters = {}
        self._sort_col = None
        self._hide_clean = False
        self._apply_header_labels()
        self.btn_csv.setEnabled(False)
        self.btn_html.setEnabled(False)
        self.btn_run.setText("취소")
        self.pbar.setVisible(True)
        self.pbar.setRange(0, len(files))
        self.pbar.setValue(0)
        self.status.setText(f"스캔 중… 총 {len(files)}개 파일 (격리 실행)")
        self.worker = BatchWorker(files, "")
        self.worker.progress.connect(self._on_progress)
        self.worker.finished_all.connect(self._on_done)
        self.worker.start()

    def _on_progress(self, idx, total, result):
        result.file_bytes = b""     # 메모리 절약(리포트엔 불필요)
        self._results.append(result)
        crit = [f for f in result.findings if "CRITICAL" in f or "HIGH" in f or "WARNING" in f]
        verdict = "⚠ 의심" if crit else ("· 참고" if result.findings else "✓ 정상")
        summary = crit[0][:80] if crit else (result.findings[0][:80] if result.findings else "특이사항 없음")
        path = self._files[idx - 1] if 0 <= idx - 1 < len(self._files) else result.filename
        self._rows.append({
            "idx": idx, "verdict": verdict, "filename": result.filename,
            "fmt": result.carrier_fmt, "size": result.filesize,
            "summary": summary, "path": path, "crit": bool(crit),
        })
        self._refresh_table()
        # 병렬 실행이라 idx(원래 번호)는 완료 순서가 아님 → 진행률은 완료 개수로
        self.pbar.setValue(len(self._results))
        self.status.setText(f"스캔 중… {len(self._results)}/{total} (격리 실행, 동시 {engine.default_workers()}개)")

    # ---------------- 정렬·필터 ----------------
    def _on_header(self, col):
        if col in (_COL_NAME, _COL_SIZE):               # 정렬 토글
            if self._sort_col == col:
                self._sort_desc = not self._sort_desc
            else:
                self._sort_col, self._sort_desc = col, False
            self._refresh_table()
        elif col in (_COL_VERDICT, _COL_FMT):           # 값 필터
            self._show_filter_menu(col)
        elif col == _COL_SUMMARY:                       # '특이사항 없음' 숨김 토글
            self._hide_clean = not self._hide_clean
            self._refresh_table()

    def _show_filter_menu(self, col):
        key = "verdict" if col == _COL_VERDICT else "fmt"
        vals = sorted(set(r[key] for r in self._rows))
        if not vals:
            return
        menu = QMenu(self)
        a_all = menu.addAction("전체 표시")
        menu.addSeparator()
        cur = self._filters.get(col)
        amap = {}
        for v in vals:
            a = menu.addAction(("● " if v == cur else "    ") + v)
            amap[a] = v
        hh = self.table.horizontalHeader()
        pos = hh.mapToGlobal(QPoint(hh.sectionViewportPosition(col), hh.height()))
        chosen = menu.exec(pos)
        if chosen is a_all:
            self._filters.pop(col, None)
            self._refresh_table()
        elif chosen in amap:
            self._filters[col] = amap[chosen]
            self._refresh_table()

    def _visible_rows(self):
        rows = list(self._rows)
        for col, val in self._filters.items():
            key = "verdict" if col == _COL_VERDICT else "fmt"
            rows = [r for r in rows if r[key] == val]
        if self._hide_clean:
            rows = [r for r in rows if r["summary"] != "특이사항 없음"]
        if self._sort_col == _COL_NAME:
            rows.sort(key=lambda r: r["filename"].lower(), reverse=self._sort_desc)
        elif self._sort_col == _COL_SIZE:
            rows.sort(key=lambda r: r["size"], reverse=self._sort_desc)
        else:
            rows.sort(key=lambda r: r["idx"])      # 병렬 완료 순서와 무관하게 원래 파일 순서
        return rows

    def _refresh_table(self):
        rows = self._visible_rows()
        self.table.setRowCount(0)
        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            vals = [str(r["idx"]), r["verdict"], r["filename"], r["fmt"], f"{r['size']:,}", r["summary"]]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == _COL_VERDICT and r["crit"]:
                    it.setForeground(Qt.red)
                if c == 0:
                    it.setData(Qt.UserRole, r["path"])   # 더블클릭용 실제 경로
                self.table.setItem(row, c, it)
        self._apply_header_labels()

    def _apply_header_labels(self):
        labels = list(_HEADERS)
        if self._sort_col in (_COL_NAME, _COL_SIZE):
            labels[self._sort_col] += " ▼" if self._sort_desc else " ▲"
        for c in (_COL_VERDICT, _COL_FMT):
            if c in self._filters:
                labels[c] += " ⧩"
        if self._hide_clean:
            labels[_COL_SUMMARY] += " (정상숨김)"
        self.table.setHorizontalHeaderLabels(labels)

    def _on_done(self, total):
        self.btn_run.setText("일괄 스캔 시작")
        self.btn_run.setEnabled(True)
        self.pbar.setVisible(False)
        self.btn_csv.setEnabled(bool(self._results))
        self.btn_html.setEnabled(bool(self._results))
        shown = len(self._visible_rows())
        extra = f" (표시 {shown}/{len(self._rows)})" if shown != len(self._rows) else ""
        cancelled = " — 취소됨" if total < len(self._files) else ""
        self.status.setText(f"일괄 스캔 완료 — {total}/{len(self._files)}개 처리{cancelled}{extra}")

    def _on_double_click(self, index):
        it = self.table.item(index.row(), 0)
        if it:
            path = it.data(Qt.UserRole)
            if path:
                self.open_in_scanner.emit(path)

    def _export(self, fmt):
        if not self._results:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "일괄 스캔 리포트 저장", f"batch_report.{fmt}",
            "CSV (*.csv)" if fmt == "csv" else "HTML (*.html)")
        if not path:
            return
        order = {p: i for i, p in enumerate(self._files)}
        results = sorted(self._results, key=lambda r: order.get(r.filepath, len(order)))   # 리포트는 원래 파일 순서
        content = engine.build_batch_csv(results) if fmt == "csv" else engine.build_batch_html(results)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        self.status.setText(f"리포트 저장 완료: {path}")
