"""
설정 탭 (Qt).

사용자 설정을 폼으로 편집하고 config(QSettings)에 저장한다.
저장 시 settings_changed 시그널을 보내 다른 탭(스캐너)이 즉시 반영한다.
"""

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QFormLayout, QGroupBox, QPushButton, QLineEdit,
    QLabel, QCheckBox, QSpinBox, QHBoxLayout, QComboBox, QFileDialog, QMessageBox,
)

from . import config


class SettingsTab(QWidget):
    settings_changed = Signal()

    def __init__(self):
        super().__init__()
        self._build()
        self._load()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        # 외관
        ap = QGroupBox(" 외관 ")
        af = QFormLayout(ap)
        self.cb_theme = QComboBox()
        self.cb_theme.addItem("다크 모드", "dark")
        self.cb_theme.addItem("화이트 모드", "light")
        af.addRow("테마:", self.cb_theme)
        root.addWidget(ap)

        # VirusTotal
        vt = QGroupBox(" VirusTotal ")
        vf = QFormLayout(vt)
        self.ed_vt = QLineEdit()
        self.ed_vt.setEchoMode(QLineEdit.Password)
        self.ed_vt.setPlaceholderText("API 키 (저장하면 스캐너 탭에 자동 입력)")
        vf.addRow("API 키:", self.ed_vt)
        self.chk_remember = QCheckBox("API 키를 기기에 저장")
        vf.addRow("", self.chk_remember)
        root.addWidget(vt)

        # 스캔/격리
        sc = QGroupBox(" 스캔 · 격리 ")
        sf = QFormLayout(sc)
        self.chk_isolated = QCheckBox("기본으로 샌드박스(프로세스 격리) 스캔 사용")
        sf.addRow("", self.chk_isolated)
        self.sp_timeout = QSpinBox()
        self.sp_timeout.setRange(10, 3600)
        self.sp_timeout.setSuffix(" 초")
        sf.addRow("격리 스캔 제한 시간:", self.sp_timeout)
        self.sp_mem = QSpinBox()
        self.sp_mem.setRange(128, 16384)
        self.sp_mem.setSingleStep(128)
        self.sp_mem.setSuffix(" MB")
        sf.addRow("격리 스캔 메모리 상한:", self.sp_mem)
        self.sp_strings = QSpinBox()
        self.sp_strings.setRange(2, 64)
        sf.addRow("strings 최소 길이:", self.sp_strings)
        root.addWidget(sc)

        # 저장 경로
        pz = QGroupBox(" 저장 ")
        pf = QFormLayout(pz)
        row = QHBoxLayout()
        self.ed_savedir = QLineEdit()
        self.ed_savedir.setPlaceholderText("비우면 매번 위치 선택")
        btn_dir = QPushButton("폴더…")
        btn_dir.clicked.connect(self._pick_dir)
        row.addWidget(self.ed_savedir)
        row.addWidget(btn_dir)
        pf.addRow("기본 저장 폴더:", row)
        row2 = QHBoxLayout()
        self.ed_yara = QLineEdit()
        self.ed_yara.setPlaceholderText("사용자 YARA 룰(.yar) 폴더 (YARA 설치 시 적용)")
        btn_yara = QPushButton("폴더…")
        btn_yara.clicked.connect(self._pick_yara)
        row2.addWidget(self.ed_yara)
        row2.addWidget(btn_yara)
        pf.addRow("YARA 룰 폴더:", row2)
        root.addWidget(pz)

        # 버튼
        btns = QHBoxLayout()
        self.btn_save = QPushButton("설정 저장")
        self.btn_save.setObjectName("accent")
        self.btn_save.clicked.connect(self._save)
        self.btn_reset = QPushButton("기본값으로 초기화")
        self.btn_reset.clicked.connect(self._reset)
        btns.addWidget(self.btn_save)
        btns.addWidget(self.btn_reset)
        btns.addStretch(1)
        root.addLayout(btns)

        self.status = QLabel("설정을 변경하고 [설정 저장]을 누르면 즉시 적용됩니다.")
        self.status.setObjectName("hint")
        root.addWidget(self.status)
        root.addStretch(1)

    def _pick_dir(self):
        d = QFileDialog.getExistingDirectory(self, "기본 저장 폴더 선택")
        if d:
            self.ed_savedir.setText(d)

    def _pick_yara(self):
        d = QFileDialog.getExistingDirectory(self, "YARA 룰 폴더 선택")
        if d:
            self.ed_yara.setText(d)

    def _load(self):
        """config → 폼."""
        idx = self.cb_theme.findData(config.get("theme"))
        self.cb_theme.setCurrentIndex(idx if idx >= 0 else 0)
        self.ed_vt.setText(config.get("vt_api_key"))
        self.chk_remember.setChecked(config.get("remember_vt"))
        self.chk_isolated.setChecked(config.get("isolated_default"))
        self.sp_timeout.setValue(config.get("scan_timeout"))
        self.sp_mem.setValue(config.get("mem_limit_mb"))
        self.sp_strings.setValue(config.get("strings_min_len"))
        self.ed_savedir.setText(config.get("default_save_dir"))
        self.ed_yara.setText(config.get("yara_rules_dir"))

    def _save(self):
        """폼 → config. VT 키는 '저장' 체크 시에만 보관."""
        config.set_many({
            "theme": self.cb_theme.currentData(),
            "vt_api_key": self.ed_vt.text() if self.chk_remember.isChecked() else "",
            "remember_vt": self.chk_remember.isChecked(),
            "isolated_default": self.chk_isolated.isChecked(),
            "scan_timeout": self.sp_timeout.value(),
            "mem_limit_mb": self.sp_mem.value(),
            "strings_min_len": self.sp_strings.value(),
            "default_save_dir": self.ed_savedir.text().strip(),
            "yara_rules_dir": self.ed_yara.text().strip(),
        })
        self.status.setText("저장되었습니다. 스캐너 탭에 즉시 반영됩니다.")
        self.settings_changed.emit()

    def _reset(self):
        if QMessageBox.question(self, "초기화", "모든 설정을 기본값으로 되돌릴까요?") == QMessageBox.Yes:
            config.reset()
            self._load()
            self.status.setText("기본값으로 초기화되었습니다.")
            self.settings_changed.emit()
