"""선택 의존성(PIL/YARA) 상태를 상태바 문구로 요약."""

from .. import engine


def summary():
    pil = "Pillow ✓" if engine.PIL_AVAILABLE else "Pillow ✗ (이미지 LSB/미리보기 비활성)"
    yara = "YARA ✓" if engine.YARA_ENGINE_AVAILABLE else "YARA ✗ (내장 정규식으로 폴백)"
    ole = "문서분석 ✓" if engine.docscan.OLEFILE_AVAILABLE else "문서분석 ✗ (olefile 미설치)"
    vba = "VBA ✓" if engine.docscan.OLEVBA_AVAILABLE else "VBA ✗ (oletools 미설치)"
    return f"엔진 준비   |   {pil}   |   {yara}   |   {ole}   |   {vba}   |   대상 파일은 실행하지 않습니다."
