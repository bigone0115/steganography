"""
포렌식 정밀 스캐너 탭 (Qt).
"""

import os

import io
import os

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QPixmap, QFont, QGuiApplication, QIcon
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox, QPushButton,
    QLineEdit, QLabel, QPlainTextEdit, QTableWidget, QTableWidgetItem, QSplitter,
    QTabWidget, QHeaderView, QFileDialog, QMessageBox, QAbstractItemView, QComboBox,
    QProgressBar, QCheckBox, QDialog, QScrollArea, QToolButton,
)

from .. import analysis, engine
from .workers import ScanWorker, VtWorker
from .entropy_chart import EntropyChart
from . import config

MONO = QFont("Consolas", 10)


class ScanTab(QWidget):
    def __init__(self):
        super().__init__()
        self.result = None
        self.worker = None
        self.vt_worker = None
        self.strings_min_len = 4
        self._build()
        self.setAcceptDrops(True)
        self.apply_settings()

    # ---------------- UI ----------------
    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        ctrl = QGroupBox(" 검사 대상 및 보안 조치 ")
        g = QGridLayout(ctrl)
        g.addWidget(QLabel("검사 파일:"), 0, 0)
        self.ed_path = QLineEdit()
        g.addWidget(self.ed_path, 0, 1, 1, 3)
        btn_browse = QPushButton("찾아보기")
        btn_browse.clicked.connect(self._browse)
        g.addWidget(btn_browse, 0, 4)
        self.btn_scan = QPushButton("정밀 포렌식 스캔")
        self.btn_scan.setObjectName("accent")
        self.btn_scan.clicked.connect(self._start_scan)
        g.addWidget(self.btn_scan, 0, 5)

        g.addWidget(QLabel("복호화 비밀번호:"), 1, 0)
        self.ed_pw = QLineEdit()
        self.ed_pw.setEchoMode(QLineEdit.Password)
        g.addWidget(self.ed_pw, 1, 1)
        g.addWidget(QLabel("VirusTotal API Key:"), 1, 2)
        self.ed_vt = QLineEdit()
        self.ed_vt.setEchoMode(QLineEdit.Password)
        g.addWidget(self.ed_vt, 1, 3)
        self.btn_vt = QPushButton("VT 해시 조회")
        self.btn_vt.clicked.connect(self._query_vt)
        g.addWidget(self.btn_vt, 1, 4)
        self.btn_extract = QPushButton("선택 항목 추출 저장")
        self.btn_extract.setObjectName("danger")
        self.btn_extract.setEnabled(False)
        self.btn_extract.clicked.connect(self._extract_selected)
        g.addWidget(self.btn_extract, 1, 5)
        self.btn_cdr = QPushButton("안전 재구성 / 후미 절단 저장 (CDR)")
        self.btn_cdr.setObjectName("success")
        self.btn_cdr.setEnabled(False)
        self.btn_cdr.clicked.connect(self._run_cdr)
        g.addWidget(self.btn_cdr, 2, 5)

        rep = QHBoxLayout()
        self.btn_html = QPushButton("HTML 리포트 저장")
        self.btn_html.setEnabled(False)
        self.btn_html.clicked.connect(lambda: self._export_report("html"))
        self.btn_json = QPushButton("JSON 리포트 저장")
        self.btn_json.setEnabled(False)
        self.btn_json.clicked.connect(lambda: self._export_report("json"))
        rep.addWidget(self.btn_html)
        rep.addWidget(self.btn_json)
        self.chk_isolated = QCheckBox("샌드박스(프로세스 격리) 스캔")
        self.chk_isolated.setChecked(True)
        self.chk_isolated.setToolTip("스캔을 별도 프로세스에서 실행해 파서 크래시·자원고갈로부터 본체를 보호합니다.")
        rep.addWidget(self.chk_isolated)
        rep.addStretch(1)
        g.addLayout(rep, 2, 0, 1, 5)
        root.addWidget(ctrl)

        # 해시 바 (복사 지원)
        hashbar = QGroupBox(" 파일 해시 ")
        hb = QGridLayout(hashbar)
        self.ed_hash = {}
        for i, algo in enumerate(("MD5", "SHA-1", "SHA-256")):
            hb.addWidget(QLabel(algo + ":"), i, 0)
            ed = QLineEdit()
            ed.setReadOnly(True)
            self.ed_hash[algo] = ed
            hb.addWidget(ed, i, 1)
            btn = QPushButton("복사")
            btn.clicked.connect(lambda _=False, a=algo: self._copy_hash(a))
            hb.addWidget(btn, i, 2)
        hb.setColumnStretch(1, 1)
        root.addWidget(hashbar)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(4)
        root.addWidget(self.progress)

        # 메인 스플리터 (좌: 목록+로그 / 우: 인스펙터)
        split = QSplitter(Qt.Horizontal)
        root.addWidget(split, 1)

        left = QSplitter(Qt.Vertical)

        tbl_box = QGroupBox(" 탐지된 은닉 파일 / 미디어 / 코드 목록 ")
        tbl_l = QVBoxLayout(tbl_box)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["#", "기법", "포맷/언어", "오프셋", "크기(B)", "세부"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(5, QHeaderView.Stretch)
        for c in (0, 1, 2, 3, 4):
            hh.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._on_select)
        self.table.itemDoubleClicked.connect(self._on_row_double)
        tbl_l.addWidget(self.table)
        left.addWidget(tbl_box)

        log_box = QGroupBox(" 통합 포렌식 스캔 리포트 ")
        log_l = QVBoxLayout(log_box)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        log_l.addWidget(self.txt_log)
        left.addWidget(log_box)
        left.setSizes([260, 420])
        split.addWidget(left)

        # 인스펙터
        insp = QTabWidget()
        code_tab = QWidget()
        cl = QVBoxLayout(code_tab)
        cl.setContentsMargins(0, 0, 0, 0)
        self.txt_code = QPlainTextEdit()
        self.txt_code.setReadOnly(True)
        cl.addWidget(self.txt_code, 1)
        crow = QHBoxLayout()
        self.lbl_code_edit = QLabel("")
        self.lbl_code_edit.setObjectName("hint")
        self.lbl_code_edit.setWordWrap(True)
        crow.addWidget(self.lbl_code_edit, 1)
        self.btn_save_code = QPushButton("수정한 코드 저장")
        self.btn_save_code.setToolTip("수정한 코드를 별도 파일로 내보냅니다 (원본 미변경).")
        self.btn_save_code.setEnabled(False)
        self.btn_save_code.clicked.connect(self._save_code)
        crow.addWidget(self.btn_save_code)
        self.btn_reinject = QPushButton("원본에 되써넣기(재삽입)")
        self.btn_reinject.setObjectName("danger")
        self.btn_reinject.setToolTip("수정한 코드를 원본과 같은 은닉 방식으로 다시 써넣어 새 파일로 저장합니다.")
        self.btn_reinject.setEnabled(False)
        self.btn_reinject.clicked.connect(self._reinject)
        crow.addWidget(self.btn_reinject)
        cl.addLayout(crow)
        insp.addTab(code_tab, "📄 코드 / Hex 뷰어")

        img_tab = QWidget()
        il = QVBoxLayout(img_tab)
        il.setContentsMargins(0, 0, 0, 0)
        self.lbl_img = QLabel("은닉 이미지가 탐지되면 여기에 표시됩니다.")
        self.lbl_img.setAlignment(Qt.AlignCenter)
        self.lbl_img.setWordWrap(True)
        il.addWidget(self.lbl_img, 1)
        self.lbl_gallery_hint = QLabel("은닉 이미지 갤러리 — 썸네일/행을 클릭(또는 더블클릭)하면 새 창에서 원본 크기로 열립니다.")
        self.lbl_gallery_hint.setObjectName("hint")
        self.lbl_gallery_hint.setWordWrap(True)
        self.lbl_gallery_hint.setVisible(False)
        il.addWidget(self.lbl_gallery_hint)
        self.gallery_scroll = QScrollArea()
        self.gallery_scroll.setWidgetResizable(True)
        self.gallery_scroll.setFixedHeight(140)
        self.gallery_scroll.setVisible(False)
        self.gallery_host = QWidget()
        self.gallery_layout = QHBoxLayout(self.gallery_host)
        self.gallery_layout.setAlignment(Qt.AlignLeft)
        self.gallery_scroll.setWidget(self.gallery_host)
        il.addWidget(self.gallery_scroll)
        insp.addTab(img_tab, "🖼️ 이미지 뷰어")

        self.txt_meta = QPlainTextEdit()
        self.txt_meta.setReadOnly(True)
        insp.addTab(self.txt_meta, "🧩 메타데이터 / 청크")

        # 비트 평면 탭
        bp = QWidget()
        bp_l = QVBoxLayout(bp)
        bp_ctrl = QHBoxLayout()
        bp_ctrl.addWidget(QLabel("채널:"))
        self.cb_channel = QComboBox()
        self.cb_channel.addItems(["Red (R)", "Green (G)", "Blue (B)", "Grayscale"])
        bp_ctrl.addWidget(self.cb_channel)
        bp_ctrl.addWidget(QLabel("비트:"))
        self.cb_bit = QComboBox()
        self.cb_bit.addItems([f"Bit {i}" + (" (LSB)" if i == 0 else " (MSB)" if i == 7 else "") for i in range(8)])
        bp_ctrl.addWidget(self.cb_bit)
        bp_ctrl.addStretch(1)
        bp_l.addLayout(bp_ctrl)
        self.lbl_bitplane = QLabel("이미지 파일을 스캔하면 비트 평면이 표시됩니다.")
        self.lbl_bitplane.setAlignment(Qt.AlignCenter)
        self.lbl_bitplane.setWordWrap(True)
        bp_l.addWidget(self.lbl_bitplane, 1)
        self.cb_channel.currentIndexChanged.connect(self._render_bitplane)
        self.cb_bit.currentIndexChanged.connect(self._render_bitplane)
        insp.addTab(bp, "🔬 비트 평면")

        # 엔트로피 차트 탭
        self.entropy_chart = EntropyChart()
        insp.addTab(self.entropy_chart, "📈 엔트로피 차트")

        # 문자열(strings) 탭
        self.txt_strings = QPlainTextEdit()
        self.txt_strings.setReadOnly(True)
        insp.addTab(self.txt_strings, "🔤 문자열(strings)")

        self.inspector = insp
        split.addWidget(insp)
        split.setSizes([620, 620])

        self.status = QLabel("파일을 선택하고 [정밀 포렌식 스캔]을 누르세요.")
        self.status.setObjectName("hint")
        root.addWidget(self.status)

    # ---------------- 동작 ----------------
    def _browse(self):
        # 기본 필터를 '모든 파일'로 — 엔진이 내용으로 포맷을 판별하므로 .unknown 등 위장 확장자도 선택 가능해야 함.
        path, _ = QFileDialog.getOpenFileName(
            self, "검사할 파일 선택", "",
            "모든 파일 (*.*);;미디어/문서 (*.png *.jpg *.jpeg *.bmp *.gif *.webp *.wav *.mp3 *.mp4 *.mkv *.avi *.mov *.webm *.pdf *.pyc)",
            "", QFileDialog.DontUseNativeDialog)
        if path:
            self.ed_path.setText(path)

    def apply_settings(self):
        """설정(config)을 UI에 반영 — VT 키 자동입력, 격리 기본값, strings 길이."""
        if config.get("remember_vt"):
            key = config.get("vt_api_key")
            if key:
                self.ed_vt.setText(key)
        self.chk_isolated.setChecked(config.get("isolated_default"))
        self.strings_min_len = config.get("strings_min_len")

    def _default_save(self, name):
        """기본 저장 폴더가 설정돼 있으면 그 경로를, 아니면 파일명만 반환."""
        import os as _os
        d = config.get("default_save_dir")
        return _os.path.join(d, name) if d and _os.path.isdir(d) else name

    def load_and_scan(self, path):
        """외부(일괄 탭 등)에서 파일 경로를 받아 바로 스캔."""
        self.ed_path.setText(path)
        self._start_scan()

    def _start_scan(self):
        path = self.ed_path.text().strip()
        if not os.path.isfile(path):
            QMessageBox.warning(self, "입력 오류", "검사할 파일을 올바르게 선택해주세요.")
            return
        self.btn_scan.setEnabled(False)
        self.btn_extract.setEnabled(False)
        self.btn_cdr.setEnabled(False)
        self.btn_html.setEnabled(False)
        self.btn_json.setEnabled(False)
        self.table.setRowCount(0)
        self.txt_log.clear()
        self.txt_code.clear()
        self._set_code_editable(False, None)
        self.txt_meta.clear()
        self.txt_strings.clear()
        for ed in self.ed_hash.values():
            ed.clear()
        self.lbl_img.setPixmap(QPixmap())
        self.lbl_img.setText("…")
        self._clear_gallery()
        self.lbl_bitplane.setPixmap(QPixmap())
        self.lbl_bitplane.setText("…")
        self.entropy_chart.clear()
        self.progress.setRange(0, 0)   # 불확정 진행(busy) 표시
        self.progress.setVisible(True)
        self.status.setText("스캔 중…")

        self.worker = ScanWorker(
            path, self.ed_pw.text(), isolated=self.chk_isolated.isChecked(),
            timeout=config.get("scan_timeout"), mem_limit_mb=config.get("mem_limit_mb"))
        self.worker.log.connect(self._append_log)
        self.worker.finished_ok.connect(self._on_scan_done)
        self.worker.failed.connect(self._on_scan_fail)
        self.worker.start()

    def _append_log(self, line):
        self.txt_log.appendPlainText(line)

    def _on_scan_fail(self, msg):
        self.btn_scan.setEnabled(True)
        self.progress.setVisible(False)
        self.status.setText("스캔 실패")
        QMessageBox.critical(self, "스캔 오류", msg)

    def _on_scan_done(self, result):
        self.result = result
        self.btn_scan.setEnabled(True)
        self.btn_cdr.setEnabled(True)
        self.btn_html.setEnabled(True)
        self.btn_json.setEnabled(True)
        self.progress.setVisible(False)
        self.ed_hash["MD5"].setText(result.md5)
        self.ed_hash["SHA-1"].setText(result.sha1)
        self.ed_hash["SHA-256"].setText(result.sha256)
        self.txt_meta.setPlainText(result.meta_report)
        self.entropy_chart.set_data(result.file_bytes, result.natural_eof)
        self._render_bitplane()
        for it in result.carved:
            row = self.table.rowCount()
            self.table.insertRow(row)
            vals = [str(it.id), it.category, it.format, it.offset, f"{it.size:,}", it.detail]
            for c, v in enumerate(vals):
                self.table.setItem(row, c, QTableWidgetItem(v))
        self._build_gallery()
        n = len(result.carved)
        crit = sum(1 for f in result.findings if "CRITICAL" in f or "HIGH" in f)
        if n:
            self.table.selectRow(0)
            self.btn_extract.setEnabled(True)
            self.status.setText(f"스캔 완료 — 탐지 항목 {n}개, 주요 경보 {crit}건")
        else:
            self.status.setText(f"스캔 완료 — 탐지 항목 없음 (경보 {len(result.findings)}건은 리포트 참고)")

    def _current_item(self):
        if not self.result:
            return None
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        rid = int(self.table.item(rows[0].row(), 0).text())
        return next((x for x in self.result.carved if x.id == rid), None)

    def _on_select(self):
        item = self._current_item()
        if not item:
            return
        self.btn_extract.setEnabled(True)
        data = item.data or b""

        # 코드/Hex 뷰어 — 인식된 코드/텍스트면 편집 가능, 이진/미디어면 Hex(읽기전용)
        media = analysis.identify_buffer_media_type(data)
        is_text = (not media) and analysis.is_text_buffer(data, item.name)
        # 편집 대상 코드: 디코딩/추출된 코드(PDF JS·OpenAction·LSB 등)가 있으면 그것, 없으면 순수 텍스트 페이로드
        if item.decoded_text and len(item.decoded_text) <= 204800:
            code_text, editable = item.decoded_text, True
        elif is_text and len(data) <= 204800:
            code_text, editable = data.decode("utf-8", "replace"), True
        else:
            code_text, editable = None, False

        if code_text is not None:
            self.txt_code.setPlainText(code_text)
        else:
            parts = []
            if media:
                parts.append(f"[이진 미디어 스트림: {media}]\n")
                parts.append(analysis.format_hex_dump(data[:4096]))
            else:
                if os.path.splitext(item.name)[1].lower() == ".pyc":
                    parts.append("[컴파일된 Python 바이트코드(.pyc) — 텍스트가 아니므로 Hex로 표시]\n")
                parts.append(analysis.format_hex_dump(data[:8192]))
            self.txt_code.setPlainText("\n".join(parts))
        self._set_code_editable(editable, item)

        # 문자열(strings)
        strs = engine.extract_strings(data, min_len=self.strings_min_len)
        self.txt_strings.setPlainText(
            f"[출력 가능 문자열 {len(strs)}개 (최소 4자)]\n\n" + "\n".join(strs) if strs
            else "추출된 문자열이 없습니다.")

        # 이미지 뷰어
        pix = QPixmap()
        if pix.loadFromData(data):
            scaled = pix.scaled(self.lbl_img.width() or 480, self.lbl_img.height() or 360,
                                Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.lbl_img.setPixmap(scaled)
            self.inspector.setCurrentIndex(1)
        else:
            self.lbl_img.setPixmap(QPixmap())
            self.lbl_img.setText("이 항목은 이미지가 아닙니다. [코드/Hex 뷰어]를 확인하세요.")
            self.inspector.setCurrentIndex(0)

    def _extract_selected(self):
        item = self._current_item()
        if not item:
            QMessageBox.warning(self, "대상 없음", "먼저 탐지 항목을 선택하세요.")
            return
        self._save_item(item)

    def _save_item(self, item):
        """선택/지정한 은닉 항목(이미지·영상·코드 등 무엇이든)의 원본 바이트를 파일로 추출 저장."""
        if not item or not item.data:
            QMessageBox.warning(self, "대상 없음", "저장할 데이터가 없습니다.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "추출 항목 저장", self._default_save(item.name), "모든 파일 (*.*)")
        if path:
            with open(path, "wb") as f:
                f.write(item.data)
            QMessageBox.information(self, "저장 완료", f"복원되었습니다:\n{path}")

    def _on_row_double(self, _cell):
        """목록 행 더블클릭 → 해당 항목을 새 창(팝업)으로 원본 보기."""
        self._open_preview(self._current_item())

    def _set_code_editable(self, editable, item):
        """인식된 코드/텍스트 항목이면 코드 뷰어를 편집 가능하게 하고 저장 버튼을 켠다."""
        self._code_item = item if editable else None
        self.txt_code.setReadOnly(not editable)
        self.btn_save_code.setEnabled(editable)
        self.btn_reinject.setEnabled(editable)
        if editable:
            self.lbl_code_edit.setText(
                f"✏ 인식된 코드 — 직접 수정 후 [수정한 코드 저장]을 누르면 별도 파일로 내보냅니다 "
                f"(원본은 변경되지 않음). (#{item.id} {item.name})")
        elif item is None:
            self.lbl_code_edit.setText("")
        else:
            self.lbl_code_edit.setText("이 항목은 코드/텍스트가 아니라 편집할 수 없습니다 (Hex/미디어/복호화 혼합).")

    def _save_code(self):
        """편집된 코드 텍스트를 파일로 저장."""
        item = getattr(self, "_code_item", None)
        if self.txt_code.isReadOnly() or not item:
            return
        text = self.txt_code.toPlainText()
        name, ext = os.path.splitext(item.name)
        default = f"{name}_edited{ext or '.txt'}"
        path, _ = QFileDialog.getSaveFileName(self, "수정한 코드 저장", self._default_save(default), "모든 파일 (*.*)")
        if path:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(text)
            QMessageBox.information(
                self, "저장 완료",
                f"수정한 코드를 별도 파일로 저장했습니다 (원본 파일은 그대로):\n{path}")

    def _reinject_bytes(self, item, edited):
        """수정한 코드(edited bytes)를 원본과 같은 은닉 방식으로 되써넣은 새 캐리어 바이트를 반환.
        반환: (new_bytes, 설명) 또는 (None, 사유). 손상 위험이 있으면 호출부에서 경고 후 진행."""
        carrier = self.result.file_bytes
        pw = self.ed_pw.text()
        cat = item.category or ""
        if "LSB" in cat:
            from .. import embed
            new_bytes, _, note = embed.embed_pixelcode_lsb(self.result.filepath, item.name, edited, pw)
            return new_bytes, f"픽셀 LSB 재임베드 — {note}"
        if "패킷" in cat:
            from .. import crypto
            from ..constants import EOF_MAGIC
            cut = self.result.natural_eof
            return carrier[:cut] + crypto.build_packet(EOF_MAGIC, item.name, edited, pw), "EOF 패킷 재생성"
        if "PDF 구조" in cat and item.name.startswith("pdf_embedded"):
            from .. import engine
            return engine.pdf_reinject_js(carrier, int(item.offset, 16), edited), "PDF /JS 재인코딩 + xref 재생성"
        # literal 바이트 교체 (후미 결합 등 파일에 코드가 그대로 존재하는 경우)
        orig = item.data or b""
        cnt = carrier.count(orig) if orig else 0
        if cnt != 1:
            return None, (f"원본 코드 바이트를 파일에서 정확히 찾지 못했습니다(발견 {cnt}곳). "
                          "이스케이프/인코딩된 구조 내 코드는 직접 재삽입이 불안정하니 [수정한 코드 저장](내보내기)을 사용하세요.")
        new = carrier.replace(orig, edited, 1)
        if carrier.startswith(b"%PDF"):              # PDF 구조 안을 바꿨으면 xref 오프셋도 맞춰준다
            from .. import engine
            return engine._pdf_rebuild_xref(new), "바이트 교체 + xref 재생성"
        return new, "바이트 교체"

    def _reinject(self):
        """수정한 코드를 원본과 같은 은닉 방식으로 되써넣어 새 파일로 저장."""
        item = getattr(self, "_code_item", None)
        if self.txt_code.isReadOnly() or not item or not self.result:
            return
        edited = self.txt_code.toPlainText().encode("utf-8")
        # 문서 구조 내부(정상 종료 이전)의 코드는 길이 변화 시 파일 손상 위험 → 경고
        in_structure = (isinstance(item.offset, str) and item.offset.startswith("0x")
                        and int(item.offset, 16) < self.result.natural_eof and "LSB" not in (item.category or "")
                        and "PDF 구조" not in (item.category or ""))   # PDF /JS 는 xref 재생성으로 안전
        if in_structure:
            ok = QMessageBox.question(
                self, "구조 내 코드 경고",
                "이 코드는 문서 구조 내부(정상 종료 지점 이전)에 있어, 길이가 바뀌면 "
                "파일이 손상될 수 있습니다(PDF/오피스 xref·오프셋 등).\n그래도 재삽입할까요?")
            if ok != QMessageBox.Yes:
                return
        try:
            new_bytes, note = self._reinject_bytes(item, edited)
        except Exception as e:
            QMessageBox.critical(self, "재삽입 오류", str(e))
            return
        if not new_bytes:
            QMessageBox.warning(self, "재삽입 불가", note)
            return
        base, ext = os.path.splitext(self.result.filename)
        path, _ = QFileDialog.getSaveFileName(
            self, "재삽입본 저장", self._default_save(f"{base}_reinjected{ext}"),
            f"동일 포맷 (*{ext});;모든 파일 (*.*)")
        if path:
            with open(path, "wb") as f:
                f.write(new_bytes)
            QMessageBox.information(
                self, "재삽입 완료",
                f"수정한 코드를 원본에 되써넣어 새 파일로 저장했습니다 ({note}):\n{path}\n\n※ 원본은 보존됩니다.")

    def _clear_gallery(self):
        if not hasattr(self, "gallery_layout"):
            return
        while self.gallery_layout.count():
            w = self.gallery_layout.takeAt(0).widget()
            if w:
                w.deleteLater()
        self.gallery_scroll.setVisible(False)
        self.lbl_gallery_hint.setVisible(False)

    def _build_gallery(self):
        """탐지된 은닉 '이미지' 항목들을 썸네일로 나열. 클릭하면 새 창에서 원본 크기로 연다."""
        self._clear_gallery()
        if not self.result:
            return
        count = 0
        for it in self.result.carved:
            data = it.data or b""
            pix = QPixmap()
            if not (data and pix.loadFromData(data)):
                continue      # 이미지가 아닌 항목(영상/오디오/코드 등)은 갤러리에서 제외
            thumb = pix.scaled(QSize(104, 104), Qt.KeepAspectRatio, Qt.SmoothTransformation)
            btn = QToolButton()
            btn.setIcon(QIcon(thumb))
            btn.setIconSize(QSize(104, 104))
            btn.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
            btn.setText(f"#{it.id} {pix.width()}x{pix.height()}")
            btn.setToolTip(f"[{it.format}] {it.name} — 클릭하면 새 창에서 원본 보기")
            btn.clicked.connect(lambda _=False, item=it: self._open_preview(item))
            self.gallery_layout.addWidget(btn)
            count += 1
        if count:
            self.gallery_scroll.setVisible(True)
            self.lbl_gallery_hint.setVisible(True)
            self.lbl_gallery_hint.setText(
                f"은닉 이미지 갤러리 ({count}장) — 썸네일/행 클릭(또는 더블클릭)하면 새 창에서 원본 크기로 열립니다.")

    def _open_preview(self, item):
        """은닉 항목을 별도 창(비모달)으로 연다. 이미지는 원본 크기, 영상/바이너리는 추출 버튼 제공."""
        if not item:
            return
        data = item.data or b""
        dlg = QDialog(self)
        dlg.setWindowTitle(f"은닉 항목 보기 — [{item.format}] {item.name}")
        dlg.resize(840, 660)
        v = QVBoxLayout(dlg)
        info = QLabel(f"기법: {item.category}   |   포맷: {item.format}   |   오프셋: {item.offset}   |   "
                      f"크기: {item.size:,} B   |   파일명: {item.name}")
        info.setWordWrap(True)
        v.addWidget(info)
        pix = QPixmap()
        if data and pix.loadFromData(data):
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            lbl = QLabel()
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setPixmap(pix)                        # 원본 크기(스크롤로 탐색)
            scroll.setWidget(lbl)
            v.addWidget(scroll, 1)
            cap = QLabel(f"원본 해상도: {pix.width()} x {pix.height()} px")
            cap.setObjectName("hint")
            v.addWidget(cap)
        else:
            ph = QLabel("이 항목은 이미지가 아니라 미리보기를 지원하지 않습니다.\n"
                        "(영상·오디오·바이너리 등) 아래 [추출 저장]으로 원본을 꺼내 외부 플레이어/도구로 확인하세요.")
            ph.setAlignment(Qt.AlignCenter)
            ph.setWordWrap(True)
            v.addWidget(ph, 1)
        row = QHBoxLayout()
        row.addStretch(1)
        btn_save = QPushButton("추출 저장")
        btn_save.setObjectName("danger")
        btn_save.clicked.connect(lambda: self._save_item(item))
        row.addWidget(btn_save)
        btn_close = QPushButton("닫기")
        btn_close.clicked.connect(dlg.close)
        row.addWidget(btn_close)
        v.addLayout(row)
        dlg.show()                                     # 비모달 → 여러 장 동시에 띄워 비교 가능
        self._preview_dlgs = getattr(self, "_preview_dlgs", [])
        self._preview_dlgs.append(dlg)                 # 참조 유지(가비지 컬렉션 방지)

    def _copy_hash(self, algo):
        val = self.ed_hash[algo].text()
        if val:
            QGuiApplication.clipboard().setText(val)
            self.status.setText(f"{algo} 해시를 클립보드에 복사했습니다.")

    def _export_report(self, fmt):
        if not self.result:
            return
        base = os.path.splitext(self.result.filename)[0]
        if fmt == "html":
            path, _ = QFileDialog.getSaveFileName(self, "HTML 리포트 저장", self._default_save(f"{base}_report.html"), "HTML (*.html)")
            content = engine.build_report_html(self.result)
        else:
            path, _ = QFileDialog.getSaveFileName(self, "JSON 리포트 저장", self._default_save(f"{base}_report.json"), "JSON (*.json)")
            content = engine.build_report_json(self.result)
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self.status.setText(f"리포트 저장 완료: {path}")
        QMessageBox.information(self, "리포트 저장", f"저장 완료:\n{path}")

    # ---- 드래그&드롭 ----
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.isfile(path):
                self.load_and_scan(path)

    def _render_bitplane(self):
        if not self.result:
            return
        ext = os.path.splitext(self.result.filepath)[1].lower()
        if ext not in (".png", ".bmp", ".jpg", ".jpeg", ".webp"):
            self.lbl_bitplane.setPixmap(QPixmap())
            self.lbl_bitplane.setText("현재 대상은 이미지가 아니므로 비트 평면을 지원하지 않습니다.")
            return
        if not engine.PIL_AVAILABLE:
            self.lbl_bitplane.setText("Pillow 미설치 — 비트 평면 비활성화 (pip install pillow)")
            return
        try:
            pil = engine.bit_plane_lut_image(self.result.filepath, self.cb_channel.currentIndex(), self.cb_bit.currentIndex())
            buf = io.BytesIO()
            pil.save(buf, format="PNG")
            pix = QPixmap()
            pix.loadFromData(buf.getvalue())
            tw = self.lbl_bitplane.width() or 440
            th = self.lbl_bitplane.height() or 320
            self.lbl_bitplane.setPixmap(pix.scaled(tw, th, Qt.KeepAspectRatio, Qt.FastTransformation))
        except Exception as e:
            self.lbl_bitplane.setText(f"비트 평면 렌더링 오류: {e}")

    def _run_cdr(self):
        if not self.result:
            return
        import os
        base = os.path.splitext(self.result.filename)[0]
        ext = os.path.splitext(self.result.filepath)[1].lower()
        path, _ = QFileDialog.getSaveFileName(self, "안전 재구성 / 후미 절단 저장", self._default_save(f"{base}_cleaned{ext}"), f"동일 포맷 (*{ext});;모든 파일 (*.*)")
        if not path:
            return
        try:
            out_bytes, info = engine.cdr_sanitize(self.result.file_bytes, self.result.filepath, self.result.natural_eof)
            with open(path, "wb") as f:
                f.write(out_bytes)
        except Exception as e:
            QMessageBox.critical(self, "CDR 오류", f"재구성 중 오류: {e}")
            return
        self.txt_log.appendPlainText(f"\n[CDR] {info}\n[CDR] 저장: {path} ({len(out_bytes):,} bytes)")
        QMessageBox.information(self, "CDR 완료", f"{info}\n\n저장 경로: {path}")

    def _query_vt(self):
        api_key = self.ed_vt.text().strip()
        if not api_key:
            QMessageBox.warning(self, "API Key 필요", "VirusTotal API Key를 입력해주세요.")
            return
        item = self._current_item()
        data = item.data if item else (self.result.file_bytes if self.result else None)
        if not data:
            QMessageBox.warning(self, "대상 없음", "먼저 파일을 스캔하세요.")
            return
        self.btn_vt.setEnabled(False)
        self.status.setText("VirusTotal 조회 중… (해시만 전송)")
        self.vt_worker = VtWorker(data, api_key)
        self.vt_worker.done.connect(self._on_vt)
        self.vt_worker.start()

    def _on_vt(self, msg, is_err):
        self.btn_vt.setEnabled(True)
        self.txt_log.appendPlainText("\n" + msg)
        self.status.setText("VirusTotal 조회 완료")
        if is_err:
            QMessageBox.warning(self, "VirusTotal", msg)
