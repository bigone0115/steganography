"""
메타데이터 편집/삭제(스크럽) — 이미지(JPEG/PNG)/PDF/OOXML(Office)/MP3/MP4.
프라이버시·무해화용: 픽셀·본문은 보존하고 메타데이터만 제거/수정한다.

- read_metadata(data) -> (포맷라벨, 행[(key, value)])     : 편집 UI 표시용
- scrub(data)         -> (new_bytes, info)                : 모든 메타데이터 제거(무손실) + 재검사 결과
- edit(data, changes) -> (new_bytes, info)                : {key: value} 필드 수정 (값을 비우면 해당 필드 삭제)

전부 바이트/구조 레벨 무손실(재인코딩 없음). 적용 못 한 키는 info에 '미적용'으로 알린다(조용히 무시 금지).
"""
import io
import re
import struct
import zipfile
import xml.etree.ElementTree as ET

try:
    from PIL import Image
    from PIL.ExifTags import TAGS as _EXIF_TAGS
    _PIL = True
    _EXIF_NAME2ID = {v: k for k, v in _EXIF_TAGS.items()}
except Exception:
    _PIL = False
    _EXIF_NAME2ID = {}

from . import engine


# =========================================================================
# 포맷 판별 + 읽기
# =========================================================================
def detect_format(data):
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:4] == b"PK\x03\x04":
        return "hwpx" if b"application/hwp+zip" in data[:200] else "ooxml"
    if data[:3] == b"ID3" or (data[-128:-125] == b"TAG" and data[:1] == b"\xff" and data[1] & 0xE0 == 0xE0):
        return "mp3"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        # HEIF/AVIF도 ftyp로 시작하지만 최상위 meta가 이미지 본체 정보 → MP4 방식으로 지우면 파일이 망가짐
        return "heif" if data[8:12] in engine.HEIF_BRANDS else "mp4"
    if data[:4] == b"RIFF" and data[8:12] in (b"WEBP", b"WAVE"):
        return "webp" if data[8:12] == b"WEBP" else "wav"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    return ""


_FMT_LABEL = {"jpeg": "JPEG 이미지", "png": "PNG 이미지", "pdf": "PDF 문서", "ooxml": "Office 문서(OOXML)",
              "hwpx": "한글 문서(HWPX)", "mp3": "MP3 오디오", "mp4": "MP4/MOV 동영상", "heif": "HEIC/AVIF 이미지",
              "webp": "WebP 이미지", "wav": "WAV 오디오", "tiff": "TIFF 이미지"}
_PIL_FMTS = ("jpeg", "png", "webp", "tiff")
# 크기·내부 IFD 포인터·TIFF 이미지 구조 태그는 편집 대상이 아니고 바꾸면 파일이 깨지므로 숨김
_STRUCT_TAGS = {"크기/모드", "ExifOffset", "GPSInfo", "ImageWidth", "ImageLength", "BitsPerSample", "Compression",
                "PhotometricInterpretation", "StripOffsets", "SamplesPerPixel", "RowsPerStrip",
                "StripByteCounts", "PlanarConfiguration", "XResolution", "YResolution", "ResolutionUnit",
                "TileWidth", "TileLength", "TileOffsets", "TileByteCounts", "ExtraSamples", "SampleFormat",
                "Predictor", "FillOrder", "JPEGTables", "ColorMap", "InterColorProfile",
                "YCbCrSubSampling", "YCbCrPositioning", "NewSubfileType", "SubfileType"}


def inspect(data):
    """(포맷라벨, 행[(key, value)], 경보[]) — 경보 = 개인정보 노출 + 포렌식(편집·조작 흔적)."""
    fmt = detect_format(data)
    if fmt in _PIL_FMTS and _PIL:
        rows, alerts = engine.extract_image_metadata(Image.open(io.BytesIO(data)))
        rows = [(k, v) for k, v in rows if k not in _STRUCT_TAGS]
        return _FMT_LABEL.get(fmt, fmt), rows, alerts
    rows, alerts = engine.extract_file_metadata(data)
    return _FMT_LABEL.get(fmt, fmt or "알 수 없음"), rows, alerts


def read_metadata(data):
    """(포맷라벨, 행[(key, value)]) 반환. 편집 가능한 메타데이터 목록."""
    return inspect(data)[:2]


# 스크럽 후에도 남는 게 정상인 행(개인정보 아님, 지우면 색/표시가 깨짐)
_HARMLESS = {"DPI", "JFIF 버전", "ICC 프로파일"}


def _haystack(d):
    """잔존 검사용 '실제로 읽히는' 바이트 — ZIP은 압축 해제한 모든 파트, PDF는 Flate 스트림까지 풀어서 포함."""
    parts = [d]
    if d[:4] == b"PK\x03\x04":
        try:
            z = zipfile.ZipFile(io.BytesIO(d))
            parts += [z.read(n) for n in z.namelist()]
        except Exception:
            pass
    elif d[:5] == b"%PDF-":
        import zlib
        for m in re.finditer(rb"stream\r?\n(.*?)endstream", d, re.S):
            try:
                parts.append(zlib.decompressobj().decompress(m.group(1)))
            except zlib.error:
                pass
    return b"\x00".join(parts)


def _leaks(old_rows, new):
    """원본의 메타 '값'이 결과 파일 바이트에 그대로 남았는지 직접 검색.
    리더가 모르는 위치(비표준 청크·압축 스트림 등)에 남은 누출까지 잡는다. UTF-8/UTF-16 모두 확인."""
    hay = _haystack(new)
    hits = []
    for k, v in old_rows:
        val = str(v).split("  (")[0].strip()          # 'GPS 좌표' 행의 '(지도: …)' 꼬리 제거
        if k in _HARMLESS or len(val) < 4 or re.fullmatch(r"[\d.,:\s/+-]+", val):
            continue                                    # 짧은 값·숫자/날짜는 우연 일치가 많아 제외
        if any(val.encode(enc) in hay for enc in ("utf-8", "utf-16-le", "utf-16-be")):
            hits.append(k)
    return hits


def _residual(old, new):
    """스크럽 결과 재검사: ① 리더로 다시 읽어 남은 키 ② 원본 값이 바이트에 남았는지.
    ②가 있어야 '리더가 모르는 곳에 남은 누출'을 '잔여 없음'으로 오판하지 않는다."""
    try:
        old_rows = read_metadata(old)[1]
        left = [k for k, v in read_metadata(new)[1] if k not in _HARMLESS and str(v).strip()]
    except Exception as e:
        return f" · 재검사 실패: {e}"
    leaked = [k for k in _leaks(old_rows, new) if k not in left]
    msg = f" · 주의: 잔여 메타 {left}" if left else ""
    if leaked:
        msg += f" · 주의: 원본 값이 파일 안에 잔존 {leaked}"
    return msg or " · 재검사: 잔여 메타·원본 값 잔존 없음"


# =========================================================================
# 스크럽(전체 삭제) — 무손실
# =========================================================================
def scrub(data):
    fmt = detect_format(data)
    if fmt == "jpeg":
        new, info = _jpeg_strip(data), "JPEG EXIF(GPS·썸네일 포함)/XMP/COM 제거 (ICC·Adobe 색정보, 픽셀 무손실 보존)"
    elif fmt == "png":
        new, info = _png_strip(data), "PNG 텍스트/EXIF/시각·비표준 청크 제거 (색·투명도 유지, 픽셀 무손실 보존)"
    elif fmt == "pdf":
        new, info = _pdf_scrub(data)
    elif fmt in ("ooxml", "hwpx"):
        new = _ooxml(data, {}, scrub=True)[0]
        info = ("한글 content.hpf(작성자/저장자/일시)" if fmt == "hwpx" else "Office docProps(core/app/custom)·댓글/변경추적 작성자") \
            + " 제거, ZIP 내부 시각 초기화"
    elif fmt == "mp3":
        new, info = _mp3_strip(data), "ID3v2/ID3v1/APE 태그 제거 (오디오 프레임 보존)"
    elif fmt == "mp4":
        new, n = _mp4_strip(data)
        info = f"MP4 udta/meta/XMP 박스 {n}개 무력화 + 생성/수정 시각 0으로 (크기 보존 → 오프셋 안전)"
    elif fmt == "heif":
        new, n = _heif_strip(data)
        info = f"HEIC Exif/XMP 아이템 {n}개 비움 (크기·오프셋 불변, 이미지 데이터 무손실)"
    elif fmt in ("webp", "wav"):
        new, dropped = _riff_strip(data, fmt)
        info = f"{fmt.upper()} 메타 청크 {dropped} 제거 (영상/음성 데이터 무손실)"
    elif fmt == "tiff":
        new, info = _tiff_strip(data), "TIFF 메타 태그 제거 (동일 압축으로 재저장 — 픽셀 무손실)"
    else:
        raise ValueError("지원하지 않는 포맷(메타데이터 없음 또는 미지원)")
    return new, info + _residual(data, new)


# =========================================================================
# 편집(필드 수정)
# =========================================================================
def edit(data, changes):
    """changes: {key: new_value}. 빈 값 = 해당 필드 삭제. 반환 (new_bytes, info)."""
    fmt = detect_format(data)
    keys = list(changes)
    if fmt == "jpeg":
        new, skipped = _jpeg_edit_exif(data, changes)
        info = f"JPEG EXIF {keys} 수정 (무손실 — 압축 데이터 그대로)"
    elif fmt == "png":
        new, skipped = _png_edit_text(data, changes), []
        info = f"PNG 텍스트 청크 {keys} 수정 (무손실)"
    elif fmt == "pdf":
        try:
            new, skipped = _pdf_edit_pikepdf(data, changes)
            info = f"PDF /Info {keys} 수정 (pikepdf 재작성 — 길이 제한 없음, 이전 판 정리)"
        except _NoPikepdf:
            new, trunc, skipped, _ = _pdf_update(data, changes)
            info = f"PDF /Info {keys} 수정 (길이보존 in-place)"
            if trunc:
                info += f" · 주의: {trunc} 값이 기존 길이를 초과해 잘림"
        if re.search(rb"<x:xmpmeta\b", new) or (b"/Metadata" in new and b"/Metadata" in data):
            info += " · 참고: XMP(작성자 등)는 그대로 — 완전히 지우려면 스크럽"
    elif fmt in ("ooxml", "hwpx"):
        new, skipped = _ooxml(data, changes, scrub=False)
        info = f"{'한글' if fmt == 'hwpx' else 'Office'} 문서 속성 {keys} 수정"
    elif fmt == "mp3":
        new, skipped = _mp3_edit(data, changes)
        info = f"ID3 {keys} 수정"
    elif fmt in _FMT_LABEL:
        raise ValueError(f"{_FMT_LABEL[fmt]}는 편집 미지원 — '전체 삭제(스크럽)'만 가능")
    else:
        raise ValueError("지원하지 않는 포맷")
    if skipped:
        info += f" · 미적용(이 키는 편집 불가 — 스크럽으로 삭제): {skipped}"
    return new, info


# -------------------- JPEG --------------------
def _jpeg_segments(d):
    """SOS 이전 마커 세그먼트 [(marker, 세그먼트 바이트)] + SOS부터 끝까지(압축 데이터)."""
    segs, i = [], 2
    while i + 4 <= len(d) and d[i] == 0xFF:
        marker = d[i + 1]
        if marker == 0xDA:                      # SOS → 이후는 압축 이미지 데이터
            break
        ln = struct.unpack(">H", d[i + 2:i + 4])[0]
        segs.append((marker, d[i:i + 2 + ln]))
        i += 2 + ln
    return segs, d[i:]


def _jpeg_keep(marker, seg):
    """APP1~15·COM은 제거하되, 색 재현에 필요한 ICC(APP2)·Adobe(APP14, CMYK 변환 플래그)는 유지."""
    if marker == 0xFE or 0xE1 <= marker <= 0xEF:
        p = seg[4:]
        return (marker == 0xE2 and p.startswith(b"ICC_PROFILE\x00")) or (marker == 0xEE and p.startswith(b"Adobe"))
    return True


def _jpeg_strip(d):
    segs, rest = _jpeg_segments(d)
    return d[:2] + b"".join(s for m, s in segs if _jpeg_keep(m, s)) + rest


# 표시 라벨 → EXIF 서브 IFD(0x8769) 태그 (engine.extract_image_metadata의 라벨과 일치)
_EXIF_SUB = {"촬영일시(Original)": 0x9003, "디지털화일시": 0x9004, "렌즈모델": 0xA434,
             "본체일련번호": 0xA431, "카메라소유자": 0xA430, "렌즈일련번호": 0xA435}
_XP_TAGS = range(0x9C9B, 0x9CA0)               # XPTitle/Comment/Author/Keywords/Subject (UTF-16LE)


def _exif_value(tid, orig, val):
    """원래 타입에 맞춰 변환. 유리수·튜플(노출값 등)은 문자열로 덮으면 깨지므로 거부."""
    if tid in _XP_TAGS:
        return val.encode("utf-16-le") + b"\x00\x00"
    if isinstance(orig, int):
        return int(val)
    if orig is None or isinstance(orig, str):
        return val
    if isinstance(orig, bytes):
        return val.encode("utf-8")
    raise ValueError("숫자/유리수 태그")


def _jpeg_edit_exif(d, changes):
    """EXIF만 다시 써서 APP1 세그먼트를 교체 — 압축 데이터 그대로(재인코딩 손실 없음)."""
    if not _PIL:
        raise RuntimeError("PIL 필요")
    exif = Image.open(io.BytesIO(d)).getexif()
    skipped = []
    for key, val in changes.items():
        val = "" if val is None else str(val)
        if key in ("GPS 좌표", "GPSInfo"):
            if val.strip():
                skipped.append(key)              # 위치 위조는 지원 안 함 — 비우면 GPS 전체 삭제
            else:
                exif.pop(0x8825, None)
            continue
        if key in _EXIF_SUB:
            ifd, tid = exif.get_ifd(0x8769), _EXIF_SUB[key]
        else:
            ifd, tid = exif, _EXIF_NAME2ID.get(key)
        if tid is None:
            skipped.append(key)
            continue
        if not val:
            ifd.pop(tid, None)
            continue
        try:
            ifd[tid] = _exif_value(tid, ifd.get(tid), val)
        except ValueError:
            skipped.append(key)
    segs, rest = _jpeg_segments(d)
    segs = [(m, s) for m, s in segs if not (m == 0xE1 and s[4:10] == b"Exif\x00\x00")]
    if len(exif):
        payload = exif.tobytes()                 # b"Exif\0\0" + TIFF
        if len(payload) + 2 > 0xFFFF:
            raise ValueError("EXIF가 64KB를 초과해 저장 불가")
        app1 = b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload
        segs.insert(1 if segs and segs[0][0] == 0xE0 else 0, (0xE1, app1))   # APP0(JFIF) 바로 뒤
    return d[:2] + b"".join(s for _, s in segs) + rest, skipped


# -------------------- PNG --------------------
_PNG_META = {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"}
_PNG_KEEP = {b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT", b"pHYs", b"bKGD",
             b"acTL", b"fcTL", b"fdAT", b"cICP", b"mDCv", b"cLLi"}


def _png_iter(d):
    i = 8
    while i + 8 <= len(d):
        ln = struct.unpack(">I", d[i:i + 4])[0]
        typ = d[i + 4:i + 8]
        yield i, typ, d[i:i + 12 + ln]
        i += 12 + ln
        if typ == b"IEND":
            break


def _png_chunk(typ, payload):
    body = typ + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", _crc32(body))


def _crc32(b):
    import zlib
    return zlib.crc32(b) & 0xFFFFFFFF


def _png_strip(d):
    out = bytearray(d[:8])
    for _, typ, chunk in _png_iter(d):
        # 핵심 청크(대문자 시작)와 색·투명도·애니메이션 부가 청크만 유지. 비표준/private 청크(앱 메타·은닉 데이터)는 제거
        if typ not in _PNG_META and (not typ[0] & 0x20 or typ in _PNG_KEEP):
            out += chunk
    return bytes(out)


def _png_text_chunk(kw, value):
    """latin1로 표현 가능하면 tEXt, 아니면(한글 등) iTXt(UTF-8) 청크 생성 — tEXt는 latin1 전용 규격."""
    kwb = kw.encode("latin1", "replace")
    v = str(value)
    try:
        return _png_chunk(b"tEXt", kwb + b"\x00" + v.encode("latin1"))
    except UnicodeEncodeError:
        # iTXt: keyword \0 compflag(0) compmethod(0) lang \0 transkw \0 text(UTF-8)
        return _png_chunk(b"iTXt", kwb + b"\x00" + b"\x00\x00" + b"\x00" + b"\x00" + v.encode("utf-8"))


def _png_edit_text(d, changes):
    # 기존 tEXt/zTXt/iTXt 키워드는 교체(빈 값이면 삭제), 없으면 IEND 앞에 추가. key는 'text:<keyword>' 또는 keyword.
    want = {}
    for k, v in changes.items():
        kw = k.split(":", 1)[1] if k.startswith("text:") else k
        want[kw] = "" if v is None else str(v)
    out = bytearray(d[:8])
    seen = set()
    for _, typ, chunk in _png_iter(d):
        if typ in (b"tEXt", b"zTXt", b"iTXt"):
            kw = chunk[8:].split(b"\x00", 1)[0].decode("latin1", "replace")
            if kw in want:
                if want[kw] and kw not in seen:
                    out += _png_text_chunk(kw, want[kw])
                seen.add(kw)                       # 같은 키 중복 청크는 하나로 합침
                continue
        if typ == b"IEND":
            for kw, v in want.items():
                if kw not in seen and v:
                    out += _png_text_chunk(kw, v)
            out += chunk
            break
        out += chunk
    return bytes(out)


# -------------------- PDF (길이 보존 in-place) --------------------
def _pdf_esc(s):
    return str(s).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").encode("latin1", "replace")


def _pdf_update(d, changes, scrub_all=False):
    """/Info 값을 '길이 보존' in-place 교체 — xref 오프셋이 안 바뀌어 안전. 리터럴 (…)·16진 <…> 모두 처리.
    증분 업데이트로 같은 키가 여러 판에 남아 있으면 '전부' 교체(이전 판에 원본이 남는 누출 방지).
    scrub_all=True면 전 키 값을 비우고 비압축 XMP 패킷도 공백화.
    반환 (new, 잘린키[], 없는키[], XMP개수)."""
    out = bytearray(d)
    targets = {k: "" for k in engine.PDF_INFO_KEYS} if scrub_all else dict(changes)
    truncated, missing = [], []
    for key, val in targets.items():
        kb = re.escape(key.encode("latin1", "replace"))
        val = "" if val is None else str(val)
        hits = 0
        # 1) 리터럴 문자열 (...)
        for m in list(re.finditer(rb"/" + kb + rb"\s*\(((?:[^()\\]|\\.)*)\)", bytes(out))):
            s, e = m.start(1), m.end(1)
            nb = _pdf_esc(val)
            if len(nb) > e - s:
                truncated.append(key)
                nb = nb[:e - s]
                while (len(nb) - len(nb.rstrip(b"\\"))) % 2:   # 이스케이프 '\' 반쪽이 남으면 ')'를 먹어 구조 파손
                    nb = nb[:-1]
            out[s:e] = nb + b" " * (e - s - len(nb))
            hits += 1
        # 2) 16진 문자열 <...> — UTF-16BE(BOM FEFF) 규격. 남는 자리는 0 → null(표시 안 됨)
        for m in list(re.finditer(rb"/" + kb + rb"\s*<([0-9A-Fa-f]*)>", bytes(out))):
            s, e = m.start(1), m.end(1)
            hx = ("﻿" + val).encode("utf-16-be").hex().upper().encode("ascii") if val else b""
            if len(hx) > e - s:
                truncated.append(key)
                hx = hx[:(e - s) - (e - s) % 4]             # UTF-16 코드 단위(16진 4자리) 경계에서 자름
            out[s:e] = hx + b"0" * (e - s - len(hx))
            hits += 1
        if not hits and not scrub_all:
            missing.append(key)
    xmp = 0
    if scrub_all:
        for m in list(re.finditer(rb"<x:xmpmeta\b.*?</x:xmpmeta>", bytes(out), re.S)):
            out[m.start():m.end()] = b" " * (m.end() - m.start())   # 스트림 /Length 그대로 → 구조 안전
            xmp += 1
    return bytes(out), sorted(set(truncated)), missing, xmp


# -------------------- OOXML --------------------
# 표시키 -> (파트, XML local-name). 네임스페이스는 무시하고 local-name으로 매칭한다.
_OOXML_MAP = {
    "creator": ("docProps/core.xml", "creator"),
    "lastModifiedBy": ("docProps/core.xml", "lastModifiedBy"),
    "title": ("docProps/core.xml", "title"),
    "created": ("docProps/core.xml", "created"),
    "modified": ("docProps/core.xml", "modified"),
    "revision": ("docProps/core.xml", "revision"),
    "subject": ("docProps/core.xml", "subject"),
    "description": ("docProps/core.xml", "description"),
    "keywords": ("docProps/core.xml", "keywords"),
    "Application": ("docProps/app.xml", "Application"),
    "Company": ("docProps/app.xml", "Company"),
    "Manager": ("docProps/app.xml", "Manager"),
    "AppVersion": ("docProps/app.xml", "AppVersion"),
    "Template": ("docProps/app.xml", "Template"),
}
_OOXML_SCRUB = {
    "docProps/core.xml": {"creator", "lastModifiedBy", "title", "subject", "description",
                          "revision", "keywords", "created", "modified", "category",
                          "contentStatus", "lastPrinted"},
    "docProps/app.xml": {"Application", "Company", "Manager", "AppVersion", "Template", "HyperlinkBase"},
}
# 본문 파트의 사람 식별 정보 — 댓글/변경내용추적 작성자, 공동작성자 계정. (파트 접두사, 패턴, 치환)
_OOXML_PEOPLE = [
    ("word/", rb'(\bw\d*:(?:author|initials|userId))="[^"]*"', rb'\1=""'),
    ("ppt/commentAuthors.xml", rb'(\b(?:name|initials))="[^"]*"', rb'\1=""'),
    ("xl/comments", rb"<author>[^<]*</author>", rb"<author></author>"),
    ("xl/persons/", rb'(\b(?:displayName|userId))="[^"]*"', rb'\1=""'),
    ("Contents/header.xml", rb'(<\w+:trackChangeAuthor\b[^>]*\bname=")[^"]*"', rb'\1"'),   # HWPX 변경추적 작성자
]


def _local(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def _xml_apply(content, name, fn):
    """ElementTree로 파싱 → fn(root) → 재직렬화(정규식 아님). 네임스페이스 접두사 보존."""
    try:
        for _, (pfx, uri) in ET.iterparse(io.BytesIO(content), events=["start-ns"]):
            ET.register_namespace(pfx, uri)
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise ValueError(f"{name} XML 파싱 실패: {e}")
    fn(root)
    return ET.tostring(root, encoding="UTF-8", xml_declaration=True)


def _ooxml(d, changes, scrub):
    """반환 (new_bytes, 미적용키[]). 스크럽은 요소를 '삭제'(빈 날짜값은 Word가 손상 파일로 볼 수 있음)."""
    zin = zipfile.ZipFile(io.BytesIO(d))
    buf = io.BytesIO()
    zout = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    edits, custom, hwpx, skipped = {}, {}, {}, []
    for key, val in changes.items():
        val = "" if val is None else str(val)
        if key in _OOXML_MAP:
            part, ln = _OOXML_MAP[key]
            edits.setdefault(part, {})[ln] = val
        elif key.startswith("custom:"):
            custom[key[7:]] = val
        elif key.startswith("hwpx:"):
            hwpx[key[5:]] = val
        else:
            skipped.append(key)

    def hpf_fn(root):
        """HWPX OPF <metadata>: <opf:title>, <opf:meta name="creator|lastsaveby|CreatedDate|…">. 언어는 유지."""
        for md in root.iter():
            if _local(md.tag) != "metadata":
                continue
            for el in md:
                ln = _local(el.tag)
                key = el.get("name") if ln == "meta" else ln
                if ln == "language":
                    continue
                if scrub:
                    el.text = ""
                elif key in hwpx:
                    el.text = hwpx[key]

    def core_fn(part):
        def fn(root):
            for parent in list(root.iter()):
                for el in list(parent):
                    ln = _local(el.tag)
                    if scrub and ln in _OOXML_SCRUB[part]:
                        parent.remove(el)
                    elif not scrub and ln in edits.get(part, {}):
                        el.text = edits[part][ln]
        return fn

    def custom_fn(root):
        for p in list(root):
            if scrub:
                root.remove(p)                      # 사용자 정의 속성 전체 삭제 → <Properties/> (유효)
            elif p.get("name") in custom:
                for c in p:
                    c.text = custom[p.get("name")]

    for item in zin.infolist():
        fn_ = item.filename
        content = zin.read(fn_)
        if fn_ in _OOXML_SCRUB and (scrub or fn_ in edits):
            content = _xml_apply(content, fn_, core_fn(fn_))
        elif fn_ == "docProps/custom.xml" and (scrub or custom):
            content = _xml_apply(content, fn_, custom_fn)
        elif fn_ == "Contents/content.hpf" and (scrub or hwpx):
            content = _xml_apply(content, fn_, hpf_fn)
        elif scrub and fn_.endswith(".xml"):
            for pfx, pat, rep in _OOXML_PEOPLE:
                if fn_.startswith(pfx):
                    content = re.sub(pat, rep, content)
        if scrub:
            item.date_time = (1980, 1, 1, 0, 0, 0)   # ZIP 엔트리 시각 = 작성/저장 시각 누출
        zout.writestr(item, content)
    zout.close()
    return buf.getvalue(), skipped


# -------------------- MP3 --------------------
def _mp3_strip(d):
    """앞 ID3v2(푸터 포함), 뒤 ID3v1(128B)·APEv2 태그 제거. 오디오 프레임만 남김."""
    start = engine.id3_frames(d)[1]
    end = len(d)
    if d[end - 128:end - 125] == b"TAG":
        end -= 128
    if end - start >= 32 and d[end - 32:end - 24] == b"APETAGEX":
        size = int.from_bytes(d[end - 20:end - 16], "little")          # 푸터 포함, 헤더 제외
        flags = int.from_bytes(d[end - 12:end - 8], "little")
        total = size + (32 if flags & 0x80000000 else 0)               # bit31 = 헤더 존재
        if 32 <= total <= end - start:
            end -= total
    return d[start:end]


_ID3_KEY = {v: k for k, v in engine.ID3_LABELS.items()}


def _id3_size(n, ver):
    if ver == 4:
        return bytes(((n >> 21) & 0x7f, (n >> 14) & 0x7f, (n >> 7) & 0x7f, n & 0x7f))
    return n.to_bytes(4, "big")


def _mp3_edit(d, changes):
    """ID3 프레임 목록에서 지정 프레임만 교체/삭제 후 태그 재작성. 원 버전(2.3/2.4) 유지,
    APIC·TXXX 등 같은 ID 여러 개인 프레임도 보존. 반환 (new, 미적용키[])."""
    ver, start, frames = engine.id3_frames(d)
    if d[:3] == b"ID3" and ver not in (3, 4):
        raise ValueError(f"ID3v2.{ver} 태그는 편집 미지원 — 스크럽만 가능")
    ver = ver or 3
    skipped = []
    for key, val in changes.items():
        fid = _ID3_KEY.get(key)
        if not fid:
            skipped.append(key)
            continue
        val = "" if val is None else str(val)
        # v2.4 = UTF-8(3), v2.3 = UTF-16 BOM(1) — v2.3에 UTF-8을 쓰면 규격 위반(엄격한 플레이어에서 깨짐)
        enc, txt, nul = (b"\x03", val.encode("utf-8"), b"\x00") if ver == 4 else \
                        (b"\x01", val.encode("utf-16"), b"\x00\x00")
        payload = enc + (b"kor" + ("".encode("utf-16") if ver == 3 else b"") + nul if fid == b"COMM" else b"") + txt
        out, done = [], False
        for f, fl, p in frames:
            if f == fid:
                if not done and val:
                    out.append((f, b"\x00\x00", payload))
                done = True                          # 같은 ID 두 번째부터는 버림(단일 텍스트 프레임)
            else:
                out.append((f, fl, p))
        if not done and val:
            out.append((fid, b"\x00\x00", payload))
        frames = out
    body = b"".join(f + _id3_size(len(p), ver) + fl + p for f, fl, p in frames)
    audio = d[start:]
    if audio[-128:-125] == b"TAG":
        audio = audio[:-128]                         # 옛 값이 남은 ID3v1은 제거(불일치 방지)
    if not body:
        return audio, skipped
    return b"ID3" + bytes((ver, 0, 0)) + _id3_size(len(body), 4) + body + audio, skipped


# -------------------- MP4 --------------------
# 박스를 '삭제'하면 moov가 mdat 앞에 있는(faststart) 파일에서 stco/co64 청크 오프셋이 어긋나 영상이 깨진다.
# → 같은 크기의 'free' 박스로 바꾸고 내용을 0으로 채운다(오프셋 불변, 모든 플레이어가 free를 무시).
_MP4_RECURSE = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts"}
_MP4_TIMES = {b"mvhd", b"tkhd", b"mdhd"}           # 생성/수정 시각(촬영 시각) 보유
_XMP_UUID = bytes.fromhex("BE7ACFCB97A942E89C71999491E3AFAC")


def _mp4_walk(buf, i, end, top):
    n = 0
    while i + 8 <= end:
        size, typ, hdr = struct.unpack(">I", buf[i:i + 4])[0], bytes(buf[i + 4:i + 8]), 8
        if size == 1:                                # 64비트 확장 크기
            if i + 16 > end:
                break
            size, hdr = struct.unpack(">Q", buf[i + 8:i + 16])[0], 16
        elif size == 0:                              # 파일 끝까지
            size = end - i
        if size < hdr or i + size > end:             # 깨진 박스 → 이후는 손대지 않음
            break
        if typ == b"udta" or (typ == b"meta" and not top) or (typ == b"uuid" and buf[i + hdr:i + hdr + 16] == _XMP_UUID):
            buf[i + 4:i + 8] = b"free"
            buf[i + hdr:i + size] = bytes(size - hdr)
            n += 1
        elif typ in _MP4_TIMES and size >= hdr + 4 + 16:
            w = 8 if buf[i + hdr] == 1 else 4        # version 1 = 64비트 시각
            buf[i + hdr + 4:i + hdr + 4 + 2 * w] = bytes(2 * w)
        elif typ in _MP4_RECURSE:
            n += _mp4_walk(buf, i + hdr, i + size, False)
        i += size
    return n


def _mp4_strip(d):
    """반환 (new_bytes, 무력화한 박스 수). 파일 크기·모든 오프셋 불변."""
    buf = bytearray(d)
    n = _mp4_walk(buf, 0, len(buf), True)
    return bytes(buf), n


# -------------------- PDF 전체 재작성 (pikepdf, 선택 의존성) --------------------
class _NoPikepdf(Exception):
    """pikepdf 미설치·암호화·열기 실패 → 길이보존 in-place 방식으로 폴백하라는 신호."""


def _pikepdf_run(d, fn):
    """pikepdf로 열어 fn(pdf) 적용 후 전체 재작성. 도달 가능한 객체만 쓰므로 증분 업데이트 이전 판이 사라진다."""
    try:
        import pikepdf
    except ImportError:
        raise _NoPikepdf
    try:
        with pikepdf.open(io.BytesIO(d)) as pdf:
            extra = fn(pdf)
            out = io.BytesIO()
            # 내용 기반 /ID, XMP는 손대지 않음(기본값이면 pikepdf가 XMP를 고치거나 비표준이면 비워버림)
            pdf.save(out, deterministic_id=True, fix_metadata_version=False)
            return out.getvalue(), extra
    except _NoPikepdf:
        raise
    except Exception:
        raise _NoPikepdf                            # 암호화·심한 손상 등 → 폴백


def _pdf_scrub(d):
    revs = max(0, d.count(b"startxref") - 1 - (1 if b"/Linearized" in d[:2048] else 0))

    def fn(pdf):
        n_annot = 0
        if "/Info" in pdf.trailer:
            del pdf.trailer["/Info"]
        for owner in [pdf.Root] + [p.obj for p in pdf.pages]:
            for k in ("/Metadata", "/PieceInfo"):       # XMP, 제작 앱 비공개 데이터(일러스트레이터 등)
                if k in owner:
                    del owner[k]
        for p in pdf.pages:
            for a in p.obj.get("/Annots", []):
                if "/T" in a:                           # 주석·메모 작성자
                    del a["/T"]
                    n_annot += 1
        names = pdf.Root.get("/Names")
        return n_annot, names is not None and "/EmbeddedFiles" in names

    try:
        new, (n_annot, embedded) = _pikepdf_run(d, fn)
    except _NoPikepdf:
        new, _, _, xmp = _pdf_update(d, {}, scrub_all=True)
        info = "PDF /Info 값 제거(증분 업데이트 이전 판 포함, 길이보존 in-place)"
        if xmp:
            info += f" · XMP 패킷 {xmp}개 공백화"
        elif re.search(rb"/Type\s*/Metadata", d):
            info += " · 주의: 압축된 XMP는 pikepdf 없이 제거 불가"
        if revs:
            info += f" · 주의: 이전 판 {revs}개의 본문은 남아 있음(pikepdf 설치 시 정리)"
        return new, info
    info = "PDF 전체 재작성(pikepdf): /Info·XMP·PieceInfo 제거"
    if n_annot:
        info += f", 주석 작성자 {n_annot}개 제거"
    if revs:
        info += f", 증분 업데이트 이전 판 {revs}개 정리"
    if embedded:
        info += " · 주의: 첨부파일(EmbeddedFiles)이 있음 — 첨부 내용은 그대로"
    return new, info


def _pdf_edit_pikepdf(d, changes):
    """/Info 편집 — 길이 제한 없음. 빈 값은 키 삭제. /Info 키 형식이 아닌 것(XMP 라벨 등)은 미적용."""
    skipped = [k for k in changes if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", k)]

    def fn(pdf):
        for k, v in changes.items():
            if k in skipped:
                continue
            if v:
                pdf.docinfo["/" + k] = str(v)
            elif "/" + k in pdf.docinfo:
                del pdf.docinfo["/" + k]

    return _pikepdf_run(d, fn)[0], skipped


# -------------------- HEIC/AVIF --------------------
_EMPTY_TIFF = b"MM\x00\x2a\x00\x00\x00\x08" + b"\x00\x00" + b"\x00\x00\x00\x00"   # 헤더 + 항목 0개 IFD


def _heif_strip(d):
    """Exif 아이템은 '빈 TIFF'로, XMP 아이템은 공백으로 같은 길이 덮어쓰기 → iloc 오프셋·파일 크기 불변."""
    buf = bytearray(d)
    items = engine.heif_meta_items(d)
    n = 0
    for off, ln in items.get("Exif", []):
        if ln < 4 + len(_EMPTY_TIFF):
            continue
        skip = int.from_bytes(buf[off:off + 4], "big")
        buf[off + 4:off + ln] = bytes(ln - 4)
        t = off + 4 + skip
        if skip == 6:
            buf[off + 4:off + 10] = b"Exif\x00\x00"
        if t + len(_EMPTY_TIFF) <= off + ln:
            buf[t:t + len(_EMPTY_TIFF)] = _EMPTY_TIFF
        n += 1
    for off, ln in items.get("XMP", []):
        buf[off:off + ln] = b" " * ln
        n += 1
    return bytes(buf), n


# -------------------- WebP / WAV (RIFF) --------------------
_RIFF_DROP = {"webp": {b"EXIF", b"XMP "},
              "wav": {b"LIST", b"bext", b"iXML", b"id3 ", b"ID3 ", b"_PMX", b"cart", b"axml"}}


def _riff_strip(d, fmt):
    """메타 청크만 빼고 RIFF 재조립(크기 필드 보정). WebP는 VP8X의 EXIF/XMP 플래그도 해제."""
    out = bytearray(d[:12])
    dropped = set()
    for cid, cs, ds, de in engine.riff_chunks(d):
        if cid in _RIFF_DROP[fmt]:
            dropped.add(cid.decode("latin1").strip())
            continue
        chunk = bytearray(d[cs:de + ((de - ds) & 1)])           # 홀수 길이 패딩 포함
        if cid == b"VP8X" and len(chunk) > 8:
            chunk[8] &= 0xFF ^ 0x0C                              # 0x08=EXIF, 0x04=XMP
        out += chunk
    out[4:8] = (len(out) - 8).to_bytes(4, "little")
    return bytes(out), sorted(dropped)


# -------------------- TIFF --------------------
def _tiff_strip(d):
    """같은 압축 방식으로 재저장 → 픽셀 무손실, Artist/Software/DateTime/XMP/IPTC 등 태그는 빠짐.
    DNG(RAW)·JPEG 압축 TIFF는 재저장 시 데이터가 손상/손실되므로 거부."""
    if not _PIL:
        raise RuntimeError("PIL 필요")
    from PIL import ImageSequence
    img = Image.open(io.BytesIO(d))
    if 50706 in img.tag_v2:
        raise ValueError("DNG(RAW)는 스크럽 미지원 — 재저장하면 RAW 데이터가 손상됨")
    comp = img.info.get("compression", "raw")
    if "jpeg" in comp:
        raise ValueError("JPEG 압축 TIFF는 무손실 스크럽 불가")
    frames = []
    for f in ImageSequence.Iterator(img):
        c = f.copy()
        c.info = {}                                              # 원본 태그(XMP/EXIF 등) 전달 차단
        frames.append(c)
    kw = {"compression": comp}
    if img.info.get("icc_profile"):
        kw["icc_profile"] = img.info["icc_profile"]
    if img.info.get("dpi"):
        kw["dpi"] = img.info["dpi"]
    buf = io.BytesIO()
    frames[0].save(buf, "TIFF", save_all=True, append_images=frames[1:], **kw)
    return buf.getvalue()
