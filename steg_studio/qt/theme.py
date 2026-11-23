"""
Qt 테마 (다크 / 화이트) QSS.

두 팔레트(DARK/LIGHT)를 제공하고 `set_mode()`로 전환한다.
set_mode는 모듈 전역 색 토큰(BASE, CRUST, BLUE ...)을 갱신하므로,
이 토큰을 직접 참조하는 EntropyChart 같은 위젯도 테마 전환 후 repaint하면 따라온다.
"""

FONT = "Malgun Gothic"
MONO = "Consolas"

# ---- 팔레트 ----
DARK = {
    "BASE": "#1e1e2e", "MANTLE": "#181825", "CRUST": "#11111b",
    "SURFACE0": "#313244", "SURFACE1": "#45475a", "SURFACE2": "#585b70",
    "TEXT": "#cdd6f4", "SUBTEXT": "#a6adc8",
    "BLUE": "#89b4fa", "LAVENDER": "#b4befe", "GREEN": "#a6e3a1",
    "RED": "#f38ba8", "YELLOW": "#f9e2af", "MAUVE": "#cba6f7", "TEAL": "#94e2d5",
    "ONACCENT": "#11111b",       # 밝은 버튼 위 글자색
    "RADIO_SEL_BG": "#2a2a40",   # 선택된 라디오 배경
}
LIGHT = {
    "BASE": "#f4f4f8", "MANTLE": "#ffffff", "CRUST": "#ffffff",
    "SURFACE0": "#e4e4ec", "SURFACE1": "#d2d2dc", "SURFACE2": "#b4b4c0",
    "TEXT": "#1e1e2e", "SUBTEXT": "#5c5f77",
    "BLUE": "#1e66f5", "LAVENDER": "#5a6fd0", "GREEN": "#40a02b",
    "RED": "#d20f39", "YELLOW": "#b8860b", "MAUVE": "#8839ef", "TEAL": "#179299",
    "ONACCENT": "#ffffff",
    "RADIO_SEL_BG": "#e3ecff",
}

# ---- 활성 토큰(초기값 DARK). set_mode가 갱신 ----
BASE = MANTLE = CRUST = SURFACE0 = SURFACE1 = SURFACE2 = ""
TEXT = SUBTEXT = BLUE = LAVENDER = GREEN = RED = YELLOW = MAUVE = TEAL = ""
ONACCENT = RADIO_SEL_BG = ""


def _build():
    """현재 활성 토큰으로 QSS 문자열을 만든다."""
    return f"""
* {{ font-family: "{FONT}"; font-size: 10pt; color: {TEXT}; outline: none; }}
QWidget {{ background: {BASE}; }}
QMainWindow, QDialog {{ background: {BASE}; }}

QTabWidget::pane {{ border: 1px solid {SURFACE0}; border-radius: 10px; top: -1px; background: {MANTLE}; }}
QTabBar::tab {{ background: {SURFACE0}; color: {SUBTEXT}; padding: 10px 22px; margin-right: 4px;
    border-top-left-radius: 9px; border-top-right-radius: 9px; font-weight: 600; }}
QTabBar::tab:selected {{ background: {BLUE}; color: {ONACCENT}; }}
QTabBar::tab:hover:!selected {{ background: {SURFACE1}; color: {TEXT}; }}

QGroupBox {{ border: 1px solid {SURFACE0}; border-radius: 10px; margin-top: 16px; padding: 12px;
    font-weight: 600; color: {BLUE}; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 14px; padding: 0 6px; }}

QPushButton {{ background: {SURFACE0}; color: {TEXT}; border: none; border-radius: 8px;
    padding: 9px 16px; font-weight: 600; }}
QPushButton:hover {{ background: {SURFACE1}; }}
QPushButton:pressed {{ background: {SURFACE2}; }}
QPushButton:disabled {{ background: {MANTLE}; color: {SURFACE2}; }}
QPushButton#accent {{ background: {BLUE}; color: {ONACCENT}; }}
QPushButton#accent:hover {{ background: {LAVENDER}; }}
QPushButton#danger {{ background: {RED}; color: {ONACCENT}; }}
QPushButton#success {{ background: {GREEN}; color: {ONACCENT}; }}

QLineEdit, QComboBox, QSpinBox {{ background: {CRUST}; border: 1px solid {SURFACE0};
    border-radius: 8px; padding: 7px 10px; selection-background-color: {BLUE}; selection-color: {ONACCENT}; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border: 1px solid {BLUE}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background: {MANTLE}; border: 1px solid {SURFACE0};
    selection-background-color: {BLUE}; selection-color: {ONACCENT}; }}

QCheckBox {{ spacing: 8px; color: {TEXT}; padding: 3px; }}
QRadioButton::indicator, QCheckBox::indicator {{ width: 16px; height: 16px; }}

QRadioButton {{ spacing: 10px; color: {SUBTEXT}; padding: 10px 12px; margin: 3px 0;
    border: 1px solid {SURFACE0}; border-radius: 8px; background: {MANTLE}; }}
QRadioButton:hover {{ background: {SURFACE0}; color: {TEXT}; }}
QRadioButton:checked {{ color: {LAVENDER}; font-weight: 700; border: 2px solid {BLUE}; background: {RADIO_SEL_BG}; }}

QPlainTextEdit, QTextEdit {{ background: {CRUST}; border: 1px solid {SURFACE0}; border-radius: 8px;
    font-family: "{MONO}"; font-size: 10pt; selection-background-color: {BLUE}; selection-color: {ONACCENT}; }}

QTableView, QTreeView {{ background: {MANTLE}; alternate-background-color: {BASE};
    border: 1px solid {SURFACE0}; border-radius: 8px; gridline-color: {SURFACE0};
    font-family: "{MONO}"; font-size: 9pt; }}
QTableView::item:selected, QTreeView::item:selected {{ background: {SURFACE1}; color: {TEXT}; }}
QHeaderView::section {{ background: {SURFACE0}; color: {BLUE}; padding: 7px; border: none; font-weight: 600; }}

QScrollBar:vertical {{ background: {MANTLE}; width: 11px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {SURFACE1}; border-radius: 5px; min-height: 28px; }}
QScrollBar::handle:vertical:hover {{ background: {SURFACE2}; }}
QScrollBar:horizontal {{ background: {MANTLE}; height: 11px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {SURFACE1}; border-radius: 5px; min-width: 28px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}

QLabel {{ color: {TEXT}; }}
QLabel#hint {{ color: {MAUVE}; }}
QStatusBar {{ background: {MANTLE}; color: {SUBTEXT}; }}
QSplitter::handle {{ background: {SURFACE0}; }}
QProgressBar {{ background: {SURFACE0}; border: none; border-radius: 2px; }}
QProgressBar::chunk {{ background: {BLUE}; }}
"""


def set_mode(mode="dark"):
    """테마 전환. mode='light'면 화이트, 그 외 다크. 전역 토큰을 갱신하고 QSS를 반환."""
    palette = LIGHT if str(mode).lower() == "light" else DARK
    globals().update(palette)
    return _build()


# 기본값: 다크 (모듈 import 시 토큰 초기화)
QSS = set_mode("dark")
