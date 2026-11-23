"""
문서형 악성코드 분석 (HWP / MS Office / OOXML) — UI 비의존.

이미지·PDF와 달리 문서 파일은 '컨테이너 구조'를 열어야 내부 위협이 보인다.
- HWP 5.x / DOC / XLS / PPT : OLE 복합문서(CFBF). olefile로 내부 스트림을 연다.
- HWPX / DOCX / XLSX / PPTX  : ZIP 컨테이너. zipfile로 내부 파트를 연다.
- VBA 매크로                 : oletools(olevba)로 추출·자동실행/의심 키워드 탐지.

engine과 순환참조를 피하기 위해 이 모듈은 engine을 import하지 않는다.
공개 함수:
    analyze_document(data, ext) -> (report:str, threats:list[str], payloads:list[dict])
    payloads 원소는 engine._add()에 바로 넣을 수 있는 형태의 dict.
"""

import io
import re
import zlib
import zipfile
import logging

# OLE 매직(CFBF): HWP 5.x / DOC / XLS / PPT 공통
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
HWP_V5_SIGNATURE = b"HWP Document File"   # HWP 5.x FileHeader 스트림 내 시그니처

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False

try:
    # olevba가 import 시 경고 로그를 많이 찍으므로 레벨 낮춤
    logging.getLogger("olevba").setLevel(logging.CRITICAL)
    from oletools.olevba import VBA_Parser
    OLEVBA_AVAILABLE = True
except Exception:
    OLEVBA_AVAILABLE = False


# 문서 내부 스트림에서 찾을 위험 신호(간이 — engine 의존 회피용)
_SUSPICIOUS_PATTERNS = [
    (rb"MZ\x90\x00", "내장 PE 실행파일"),
    (rb"\x7fELF", "내장 ELF 실행파일"),
    (rb"%!PS|%%BoundingBox|\bexec\b|\bshowpage\b", "PostScript/EPS 코드"),
    (rb"eval\s*\(|unescape\s*\(|String\.fromCharCode|ActiveXObject|WScript\.Shell", "스크립트/동적 실행"),
    (rb"powershell|cmd\.exe|/bin/sh|Invoke-Expression|DownloadString", "셸/명령 실행"),
    # 오피스/HWPX가 늘 갖는 표준 네임스페이스 호스트는 제외 (정상 문서 오탐 방지)
    (rb"(?:https?|ftp)://(?!(?:schemas\.openxmlformats\.org|schemas\.microsoft\.com|"
     rb"www\.w3\.org|purl\.org|www\.hancom\.co\.kr|ns\.adobe\.com|"
     rb"urn\.oasis\.org|docs\.oasis-open\.org)/)", "외부 URL 참조"),
]


# 문서 패키지에 정상적으로 들어갈 일이 없는 스크립트 확장자 (있으면 그 자체로 의심)
_SCRIPT_EXTS = (".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".bat", ".cmd",
                ".sh", ".py", ".pl", ".php")


def _scan_suspicious(buf):
    """바이트 버퍼에서 간이 위험 신호를 찾아 설명 리스트 반환."""
    hits = []
    for pat, desc in _SUSPICIOUS_PATTERNS:
        if re.search(pat, buf, re.IGNORECASE):
            hits.append(desc)
    return hits


def _maybe_decompress(buf, limit=8 * 1024 * 1024):
    """
    HWP BinData 등은 raw deflate(zlib)로 압축돼 있는 경우가 많다.
    raw deflate(wbits=-15)와 표준 zlib 둘 다 시도해 풀리면 압축 해제 버퍼를 반환(아니면 None).
    """
    for wbits in (-15, 15):
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(buf, limit)
            if out and len(out) > len(buf) // 2:   # 그럴듯하게 풀렸을 때만
                return out
        except Exception:
            continue
    return None


def _is_zip_office(data):
    """ZIP 기반 오피스/HWPX 여부와 종류 문자열을 (bool, 종류) 로 판별."""
    if not data.startswith(b"PK\x03\x04"):
        return False, None
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except Exception:
        return False, None
    joined = "\n".join(names)
    if "Contents/content.hpf" in joined or any(n.startswith("Contents/") for n in names):
        return True, "HWPX 문서"
    if "word/" in joined:
        return True, "DOCX 문서"
    if "xl/" in joined:
        return True, "XLSX 문서"
    if "ppt/" in joined:
        return True, "PPTX 문서"
    if "mimetype" in names:
        return True, "ODF 문서"
    return False, None


def detect_document_type(data, ext=""):
    """
    문서 포맷 종류를 식별해 문자열로 반환(아니면 None).
    OLE면 HWP 5.x / OLE 복합문서, ZIP이면 HWPX/DOCX/XLSX/PPTX 등.
    """
    if data.startswith(OLE_MAGIC):
        if HWP_V5_SIGNATURE in data[:8192]:
            return "HWP 문서(5.x)"
        return "OLE 복합문서(DOC/XLS/PPT)"
    is_zip, kind = _is_zip_office(data)
    if is_zip:
        return kind
    return None


# =========================================================================
# OLE 복합문서 (HWP 5.x / DOC / XLS / PPT)
# =========================================================================
def _analyze_ole(data, lines, threats, payloads):
    """olefile로 OLE 내부 스트림을 순회하며 HWP BinData/Scripts·의심 스트림을 분석."""
    if not OLEFILE_AVAILABLE:
        lines.append(" [!] olefile 미설치 — OLE 내부 구조 분석 불가 (pip install olefile)")
        return
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as e:
        lines.append(f" [!] OLE 파싱 실패: {e}")
        return

    is_hwp = HWP_V5_SIGNATURE in data[:8192]
    lines.append(f" • OLE 복합문서 ({'HWP 5.x' if is_hwp else 'DOC/XLS/PPT'}) 스트림 목록:")

    for entry in ole.listdir(streams=True, storages=False):
        path = "/".join(entry)
        try:
            with ole.openstream(entry) as s:
                buf = s.read(1024 * 1024)   # 스트림당 최대 1MB
        except Exception:
            continue
        lines.append(f"    - {path} ({len(buf):,} B)")

        # HWP: BinData 스트림(삽입 OLE/이미지/EXE) + Scripts(매크로)
        label = None
        if "BinData" in path:
            label = "HWP BinData(삽입 객체)"
        elif "Scripts" in path or "JScript" in path:
            label = "HWP Script(매크로)"

        # BinData는 raw deflate 압축인 경우가 많아 풀어서도 검사
        scan_buf = buf
        if "BinData" in path:
            dec = _maybe_decompress(buf)
            if dec is not None:
                lines.append(f"      ↳ 압축 해제됨 ({len(dec):,} B) — 내부 재검사")
                scan_buf = buf + b"\n" + dec   # 원본+해제본 모두 패턴 검사 대상

        hits = _scan_suspicious(scan_buf)
        if hits:
            threats.append(f"{path}: {', '.join(hits)}")
            payloads.append({
                "category": "문서 내부 위협", "fmt": label or "OLE 스트림 코드",
                "offset": path, "data": buf,
                "detail": f"{path} — {', '.join(hits)}",
                "name": path.replace("/", "_") + ".bin",
                "decoded": None,
            })
        elif label:
            # 위험 신호는 없어도 HWP 스크립트/BinData는 검토 대상으로 노출
            payloads.append({
                "category": "문서 내부 객체", "fmt": label,
                "offset": path, "data": buf,
                "detail": f"{path} — 검토 대상 스트림",
                "name": path.replace("/", "_") + ".bin", "decoded": None,
            })
    try:
        ole.close()
    except Exception:
        pass


# =========================================================================
# ZIP 기반 오피스 / HWPX
# =========================================================================
def _analyze_zip_office(data, kind, lines, threats, payloads):
    """zipfile로 내부 파트를 순회하며 스크립트·외부참조·OLE 객체·HWPX BinData 분석."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        lines.append(f" [!] ZIP 파싱 실패: {e}")
        return
    lines.append(f" • {kind} (ZIP 컨테이너) 내부 파트:")
    for name in zf.namelist():
        lines.append(f"    - {name}")
        low = name.lower()
        # vbaProject.bin → 매크로는 아래 _analyze_vba에서 통합 처리
        if low.endswith("vbaproject.bin"):
            threats.append(f"{name}: VBA 매크로 프로젝트 포함")
            continue
        # 스크립트·바이너리·외부참조가 있을 법한 파트만 열어 검사
        if low.endswith((".xml", ".rels", ".hpf", ".bin") + _SCRIPT_EXTS) or "bindata" in low or "script" in low:
            try:
                buf = zf.read(name)[:1024 * 1024]
            except Exception:
                continue
            hits = _scan_suspicious(buf)
            if low.endswith(_SCRIPT_EXTS):
                hits.insert(0, "스크립트 파일 파트")
            if hits:
                threats.append(f"{name}: {', '.join(hits)}")
                payloads.append({
                    "category": "문서 내부 위협", "fmt": "오피스/HWPX 파트",
                    "offset": name, "data": buf,
                    "detail": f"{name} — {', '.join(hits)}",
                    "name": name.replace("/", "_"), "decoded": None,
                })


# =========================================================================
# VBA 매크로 (DOC/XLS/DOCX/XLSM 등 공통)
# =========================================================================
def _analyze_vba(data, lines, threats, payloads):
    """oletools(olevba)로 VBA 매크로를 추출하고 자동실행/의심 키워드를 탐지."""
    if not OLEVBA_AVAILABLE:
        return
    try:
        vp = VBA_Parser("document", data=data)
    except Exception:
        return
    try:
        if not vp.detect_vba_macros():
            return
        lines.append(" • VBA 매크로 탐지됨:")
        for (_fn, _stream, vba_name, vba_code) in vp.extract_all_macros():
            if not vba_code:
                continue
            code_bytes = vba_code.encode("utf-8", errors="replace")
            lines.append(f"    - 매크로 모듈: {vba_name} ({len(vba_code):,} chars)")
            payloads.append({
                "category": "문서 내부 위협", "fmt": "VBA 매크로",
                "offset": vba_name, "data": code_bytes,
                "detail": f"VBA 매크로 모듈 {vba_name}",
                "name": f"{vba_name}.vba", "decoded": vba_code[:8000],
            })
        # 자동실행/의심 키워드 분석 (olevba 내장 룰)
        try:
            for (kw_type, keyword, desc) in (vp.analyze_macros() or []):
                threats.append(f"VBA[{kw_type}] {keyword}: {desc}")
        except Exception:
            pass
    finally:
        try:
            vp.close()
        except Exception:
            pass


# =========================================================================
# 공개 진입점
# =========================================================================
def analyze_document(data, ext=""):
    """
    문서(HWP/Office/OOXML)면 내부 구조를 분석해 (리포트, 위협목록, 페이로드) 반환.
    문서가 아니면 ("", [], []) 반환(엔진이 그냥 건너뛰게).
    payloads는 engine._add()에 바로 쓰는 dict 리스트(뷰어 항목으로 승격됨).
    """
    doc_type = detect_document_type(data, ext)
    is_ole = data.startswith(OLE_MAGIC)
    is_zip_office, zip_kind = _is_zip_office(data)
    if not (doc_type or is_ole or is_zip_office):
        return "", [], []

    lines = [f"=== [문서 구조 분석] {doc_type or '문서'} ===\n"]
    threats, payloads = [], []

    if is_ole:
        _analyze_ole(data, lines, threats, payloads)
    if is_zip_office:
        _analyze_zip_office(data, zip_kind, lines, threats, payloads)
    # VBA는 OLE/ZIP 모두에서 나올 수 있어 공통 호출
    _analyze_vba(data, lines, threats, payloads)

    if not threats and len(lines) <= 1:
        lines.append(" [+] 내부 스트림에서 특이 위협 신호가 발견되지 않았습니다.")
    return "\n".join(lines), threats, payloads
