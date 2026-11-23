"""
파일·코드 은닉 탭 (Qt).
"""

import os

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QGroupBox, QPushButton, QLineEdit,
    QLabel, QPlainTextEdit, QRadioButton, QButtonGroup, QFileDialog, QMessageBox,
)

from .. import embed


class EmbedTab(QWidget):
    MODES = [
        ("pixelcode", "🖼  PixelCode (이미지 픽셀 LSB)", "무손실 PNG로 저장, 알파 채널 보존. 이미지 캐리어."),
        ("audio_lsb", "🎵  Audio LSB (WAV 샘플)", "각 PCM 샘플 최하위 바이트에 은닉, 음질 손상 방지. WAV 전용."),
        ("eof_packet", "📎  EOF 패킷 결합", "파일 끝에 압축·암호화 패킷 결합. PNG/MP4/PDF 등 범용."),
        ("raw_concat", "🧬  Raw 결합 (Polyglot)", "원본 뒤에 파일을 그대로 이어붙임. 카빙 테스트용."),
    ]

    def __init__(self):
        super().__init__()
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        files = QGroupBox(" 1. 대상 파일 선택 ")
        g = QGridLayout(files)
        g.addWidget(QLabel("원본 미디어:"), 0, 0)
        self.ed_carrier = QLineEdit()
        g.addWidget(self.ed_carrier, 0, 1)
        b1 = QPushButton("찾아보기")
        b1.clicked.connect(self._pick_carrier)
        g.addWidget(b1, 0, 2)
        g.addWidget(QLabel("숨길 파일:"), 1, 0)
        self.ed_payload = QLineEdit()
        g.addWidget(self.ed_payload, 1, 1)
        b2 = QPushButton("찾아보기")
        b2.clicked.connect(self._pick_payload)
        g.addWidget(b2, 1, 2)
        root.addWidget(files)

        mode_box = QGroupBox(" 2. 은닉 기법 ")
        ml = QVBoxLayout(mode_box)
        self.lbl_selected = QLabel()
        self.lbl_selected.setObjectName("hint")
        ml.addWidget(self.lbl_selected)
        self.mode_group = QButtonGroup(self)
        self._mode_titles = {}
        for i, (key, title, desc) in enumerate(self.MODES):
            rb = QRadioButton(f"{title}\n      {desc}")
            rb.setProperty("mode_key", key)
            self._mode_titles[key] = title
            if i == 0:
                rb.setChecked(True)
            self.mode_group.addButton(rb, i)
            ml.addWidget(rb)
        self.mode_group.buttonToggled.connect(self._update_selected_label)
        self._update_selected_label()
        root.addWidget(mode_box)

        crypto_box = QGroupBox(" 3. 암호화 (PBKDF2 + 파일명/헤더 AAD HMAC 보호) ")
        cl = QGridLayout(crypto_box)
        cl.addWidget(QLabel("비밀번호 (비우면 평문 압축):"), 0, 0)
        self.ed_pw = QLineEdit()
        self.ed_pw.setEchoMode(QLineEdit.Password)
        cl.addWidget(self.ed_pw, 0, 1)
        root.addWidget(crypto_box)

        self.btn_run = QPushButton("은닉 파일 생성하기")
        self.btn_run.setObjectName("accent")
        self.btn_run.clicked.connect(self._run)
        root.addWidget(self.btn_run)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        root.addWidget(self.log, 1)

    def _pick_carrier(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "원본 미디어 선택", "",
            "지원 미디어 (*.png *.jpg *.jpeg *.bmp *.gif *.webp *.wav *.mp3 *.mp4 *.mkv *.avi *.mov *.pdf);;모든 파일 (*.*)")
        if path:
            self.ed_carrier.setText(path)
            ext = os.path.splitext(path)[1].lower()
            key = "audio_lsb" if ext == ".wav" else ("pixelcode" if ext in (".png", ".bmp", ".jpg", ".jpeg", ".webp") else "eof_packet")
            for btn in self.mode_group.buttons():
                if btn.property("mode_key") == key:
                    btn.setChecked(True)

    def _pick_payload(self):
        path, _ = QFileDialog.getOpenFileName(self, "숨길 파일 선택", "", "모든 파일 (*.*)")
        if path:
            self.ed_payload.setText(path)

    def _mode(self):
        return self.mode_group.checkedButton().property("mode_key")

    def _update_selected_label(self, *args):
        """현재 선택된 은닉 기법을 상단에 크게 표시(가독성)."""
        key = self._mode()
        self.lbl_selected.setText(f"✓ 현재 선택: {self._mode_titles.get(key, key)}")

    def _log(self, msg):
        self.log.appendPlainText(msg)

    def _run(self):
        carrier = self.ed_carrier.text().strip()
        payload = self.ed_payload.text().strip()
        if not os.path.isfile(carrier) or not os.path.isfile(payload):
            QMessageBox.warning(self, "입력 오류", "원본 미디어와 숨길 파일을 모두 선택해주세요.")
            return
        pw = self.ed_pw.text()
        mode = self._mode()
        with open(payload, "rb") as f:
            payload_bytes = f.read()

        self._log(f"[*] 원본: {carrier}")
        self._log(f"[*] 숨길 파일: {payload} ({len(payload_bytes):,} bytes)")
        self._log(f"[*] 기법: {mode} | 보호: {'암호화(v5 AAD)' if pw else '평문 압축(v5 AAD)'}")

        try:
            if mode == "pixelcode":
                out_bytes, ext, info = embed.embed_pixelcode_lsb(carrier, payload, payload_bytes, pw)
            elif mode == "audio_lsb":
                out_bytes, ext, info = embed.embed_audio_wav_lsb(carrier, payload, payload_bytes, pw)
            elif mode == "eof_packet":
                out_bytes, ext, info = embed.embed_eof_packet(carrier, payload, payload_bytes, pw)
            else:
                out_bytes, ext, info = embed.embed_raw_concat(carrier, payload_bytes)
        except Exception as e:
            self._log(f"[!] 오류: {e}")
            QMessageBox.critical(self, "은닉 실패", str(e))
            return

        save_path, _ = QFileDialog.getSaveFileName(self, "결과 저장", f"stego_output{ext}", f"결과 파일 (*{ext});;모든 파일 (*.*)")
        if not save_path:
            self._log("[-] 저장이 취소되었습니다.")
            return
        with open(save_path, "wb") as f:
            f.write(out_bytes)
        self._log(f"[+] {info}")
        self._log(f"[+] 저장 완료: {save_path} ({len(out_bytes):,} bytes)\n")
        QMessageBox.information(self, "완료", f"{info}\n\n{save_path}")
