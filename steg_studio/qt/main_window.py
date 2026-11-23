"""
Qt 메인 윈도우 — 3개 탭 조립 + 다크 테마 적용.
"""

import os

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QMainWindow, QTabWidget

from .. import __version__, engine
from . import engine_flags, config, theme
from .scan_tab import ScanTab
from .embed_tab import EmbedTab
from .batch_tab import BatchTab
from .meta_tab import MetaTab
from .settings_tab import SettingsTab

# 패키지에 번들된 프로그램 아이콘 (steg_studio/steganography_icon.png)
APP_ICON = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "steganography_icon.png")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"스테가노그래피·포렌식 보안 스튜디오 v{__version__}")
        if os.path.exists(APP_ICON):
            self.setWindowIcon(QIcon(APP_ICON))
        self.resize(1360, 900)

        tabs = QTabWidget()
        self.embed_tab = EmbedTab()
        self.scan_tab = ScanTab()
        self.batch_tab = BatchTab()
        self.meta_tab = MetaTab()
        self.settings_tab = SettingsTab()
        tabs.addTab(self.embed_tab, " 파일·코드 은닉 ")
        tabs.addTab(self.scan_tab, " 정밀 포렌식 스캐너 ")
        tabs.addTab(self.batch_tab, " 디렉터리 일괄 스캔 ")
        tabs.addTab(self.meta_tab, " 메타데이터 ")
        tabs.addTab(self.settings_tab, " ⚙ 설정 ")
        tabs.setCurrentIndex(1)
        self.tabs = tabs
        self.setCentralWidget(tabs)

        # 일괄 탭에서 더블클릭 → 스캐너 탭으로 열기
        self.batch_tab.open_in_scanner.connect(self._open_in_scanner)
        # 설정 변경 → 스캐너 탭 즉시 반영 + 테마 재적용
        self.settings_tab.settings_changed.connect(self.scan_tab.apply_settings)
        self.settings_tab.settings_changed.connect(self._apply_theme)

        self.settings_tab.settings_changed.connect(self._apply_engine_settings)

        self._apply_theme()
        self._apply_engine_settings()
        sb = self.statusBar()
        sb.showMessage(engine_flags.summary())

    def _apply_engine_settings(self):
        """엔진 측 설정(사용자 YARA 룰 폴더)을 반영."""
        engine.set_user_yara_dir(config.get("yara_rules_dir"))

    def _apply_theme(self):
        """config의 테마(다크/화이트)를 앱 전체에 적용하고 커스텀 위젯을 다시 그린다."""
        self.setStyleSheet(theme.set_mode(config.get("theme")))
        # QPainter 기반 위젯(엔트로피 차트)은 테마 토큰을 직접 참조하므로 repaint 필요
        self.scan_tab.entropy_chart.update()

    def _open_in_scanner(self, path):
        self.tabs.setCurrentWidget(self.scan_tab)
        self.scan_tab.load_and_scan(path)
