"""
앱 설정 저장/로드 (QSettings 래퍼).

QSettings는 OS 표준 위치에 저장한다(Windows=레지스트리, Linux/macOS=설정파일).
타입 보존을 위해 DEFAULTS의 기본값 타입에 맞춰 변환해 돌려준다.
"""

from PySide6.QtCore import QSettings

_ORG = "StegStudio"
_APP = "StegForensicStudio"

# 설정 키와 기본값 (기본값의 타입이 변환 기준)
DEFAULTS = {
    "theme": "dark",           # UI 테마: "dark" 또는 "light"
    "vt_api_key": "",          # VirusTotal API 키
    "remember_vt": True,       # VT 키 저장 여부
    "isolated_default": True,  # 스캔 시 프로세스 격리 기본 ON
    "scan_timeout": 180,       # 격리 스캔 제한 시간(초)
    "mem_limit_mb": 1024,      # 격리 스캔 메모리 상한(MB)
    "strings_min_len": 4,      # strings 추출 최소 길이
    "default_save_dir": "",    # 추출/리포트 기본 저장 폴더
    "yara_rules_dir": "",      # 사용자 YARA 룰(.yar) 폴더
}


def _store():
    return QSettings(_ORG, _APP)


def get(key):
    """설정값을 기본값 타입에 맞춰 반환."""
    default = DEFAULTS[key]
    val = _store().value(key, default)
    if isinstance(default, bool):
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        try:
            return int(val)
        except (TypeError, ValueError):
            return default
    return val if val is not None else default


def set_value(key, value):
    """설정값 저장."""
    _store().setValue(key, value)


def set_many(mapping):
    """여러 설정을 한 번에 저장."""
    s = _store()
    for k, v in mapping.items():
        s.setValue(k, v)


def reset():
    """모든 설정을 기본값으로 초기화."""
    s = _store()
    for k in DEFAULTS:
        s.remove(k)
