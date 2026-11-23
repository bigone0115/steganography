"""
Stego & Forensic Security Studio (v5)

이미지/오디오/문서에 파일을 은닉(스테가노그래피)하고,
숨겨진 데이터를 탐지·추출·분석하는 방어 지향 포렌식 도구.

패키지 구성(핵심 로직은 모두 UI 비의존):
- constants : 매직 시그니처, 패킷 플래그, 메모리 보호 상한선
- crypto    : 은닉 패킷 직렬화 · 암호화 · 파싱 (순수 함수)
- analysis  : 엔트로피 · 포맷 식별 · Hex 덤프 (순수 함수)
- embed     : 은닉 생성 로직
- engine    : 포렌식 스캔 엔진 → scan_file(path)
- metaedit  : 메타데이터 편집/삭제(스크럽)
- steganalysis / container / ioc / ml / video / docscan : 통계·ML 탐지 및 문서 분석
- cli       : 터미널/자동화 진입점 (python -m steg_studio)

GUI:
- qt/   : GUI(PySide6) — 실행: run.py
"""

__version__ = "5.0.0"

__all__ = ["__version__"]
