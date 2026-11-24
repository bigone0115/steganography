"""
탐지기 회귀 테스트 (합성 데이터). 실행: python tests/test_detectors.py  (pytest로도 실행 가능)
실데이터 정확도 검증이 아니라 '고장 감지'용이다.
"""
import io
import os
import sys
import math
import random
import struct
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from PIL import Image, ImageFilter
from steg_studio import steganalysis as sa, container, ioc, analysis


def _img(seed=1, w=400, h=300):
    random.seed(seed)
    n = Image.effect_noise((w, h), 50).filter(ImageFilter.GaussianBlur(1.2))
    g = Image.linear_gradient("L").resize((w, h))
    return Image.merge("RGB", [Image.blend(g, n, .4), Image.blend(g.transpose(0), n, .5), n])


def _replace(px, rate):
    b = bytearray(px)
    for i in random.sample(range(len(b)), int(len(b) * rate)):
        b[i] = (b[i] & 0xFE) | random.getrandbits(1)
    return bytes(b)


def test_rs_ws():
    img = _img()
    px, (w, h) = img.tobytes(), img.size
    assert sa.rs_analysis(px) < 0.05
    assert abs(sa.rs_analysis(_replace(px, 0.5)) - 0.5) < 0.1
    assert abs(sa.ws_analysis(_replace(px, 0.2), w, h)[0] - 0.2) < 0.06


def test_jpeg_decoder_baseline_equals_progressive():
    img = _img()
    out = []
    for prog in (False, True):
        b = io.BytesIO()
        img.save(b, "JPEG", quality=85, progressive=prog)
        out.append(sa.jpeg_dct_coefficients(b.getvalue(), max_blocks=10 ** 6))
    assert out[0] and out[0] == out[1]
    assert sa.jsteg_chi_square(out[0]) < 0.1


def test_multi_order_scan():
    img = _img()
    px = bytearray(img.tobytes())
    msg = b"\x00\x00\x00\x40Secret plan: meet at the harbor, bring the documents tonight."
    for i, bit in enumerate((c >> (7 - k)) & 1 for c in msg for k in range(8)):
        px[i] = (px[i] & 0xFE) | bit
    assert sa.multi_order_lsb_scan(bytes(px), *img.size)
    assert not sa.multi_order_lsb_scan(img.tobytes(), *img.size)


def test_audio_and_text():
    random.seed(0)
    base, v = [], 0.0
    for _ in range(40000):
        v = 0.97 * v + random.gauss(0, 800)
        base.append(v)
    echo = [int(base[i] + (0.4 * base[i - 150] if i >= 150 else 0)) for i in range(len(base))]
    z, lag = sa.echo_hiding_score(echo)
    assert z > 10 and lag == 150
    assert sa.echo_hiding_score([int(x) for x in base])[0] < 6
    n = 1024
    ph = {k: random.choice((1, -1)) * math.pi / 2 for k in range(1, 512)}
    pc = [int(sum(30 * math.cos(2 * math.pi * k * t / n + ph[k]) for k in range(1, 512, 2))) for t in range(n)]
    assert sa.phase_coding_score(pc)[0] > 0.4
    assert sa.text_stego_check("hi​‌" * 10)
    assert not sa.text_stego_check("normal text\nok")


def test_png_idat():
    img = Image.effect_noise((120, 80), 40).convert("RGB")
    b = io.BytesIO()
    img.save(b, "PNG")
    assert container.inspect(b.getvalue())[1] == []

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    raw = b"".join(b"\x00" + img.tobytes()[y * 360:(y + 1) * 360] for y in range(80))
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 120, 80, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw) + b"HIDDEN" * 10) + chunk(b"IEND", b""))
    assert container.inspect(png)[1][0][0] == "HIGH"


def test_ioc():
    r = ioc.extract_iocs(["get http://evil.example.ru/a.ps1 from 185.22.33.4"])
    assert r["url"] == ["http://evil.example.ru/a.ps1"] and r["ipv4"] == ["185.22.33.4"]


def test_binary_preview_detection():
    assert not analysis.is_text_buffer(b"\x00\x01\x02", "module.pyc")
    assert not analysis.is_text_buffer(b"\x00\x01\x02", "payload.bin")
    assert not analysis.is_text_buffer(bytes([1, 2, 3, 4, 5]), "payload.bin")
    assert analysis.is_text_buffer(b"print('hello')\n", "script.py")


def test_zip_container_not_false_carved():
    """정상 다중엔트리 ZIP(= OOXML/HWPX 구조)을 '은닉 ZIP'으로 오탐하지 않고 EOCD로 종료점을 잡는지."""
    import zipfile
    from steg_studio import engine
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", b"<xml>hi</xml>" * 20)
        z.writestr("[Content_Types].xml", b"<types/>")
    zb = buf.getvalue()
    assert zb.count(b"PK\x03\x04") >= 2                 # offset>16 에도 PK 로컬헤더 존재
    fmt, eof = engine.identify_carrier_and_eof(zb)
    assert eof == len(zb)                               # 정상 ZIP: EOCD 끝 == 파일 끝
    assert not any("ZIP" in c["label"] for c in engine.carve_embedded_media(zb, fmt, eof))
    # EOCD 뒤 결합 데이터는 natural_eof 로 분리
    _, eof2 = engine.identify_carrier_and_eof(zb + b"TRAILER_SECRET")
    assert eof2 == len(zb)
    # 무손실 PNG 뒤에 결합된 진짜 ZIP 은 여전히 포착(참 양성 유지)
    pb = io.BytesIO(); Image.effect_noise((40, 40), 30).convert("RGB").save(pb, "PNG")
    png = pb.getvalue()
    _, peof = engine.identify_carrier_and_eof(png)
    assert any("ZIP" in c["label"] for c in engine.carve_embedded_media(png + zb, "PNG 이미지", peof))


def test_docx_inserted_image_not_carved():
    """정상 DOCX에 삽입된 이미지(ZIP 내부 엔트리)를 '은닉 미디어'로 오탐하지 않는지."""
    import zipfile
    from steg_studio import engine

    def _png(w=32, h=32):
        def ch(t, d):
            return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
        raw = b"".join(b"\x00" + bytes([(x * 8) % 256 for x in range(w * 3)]) for _ in range(h))
        return (b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b""))

    png = _png()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", b"<w:document/>")
        z.writestr("word/media/image1.png", png)                                   # deflate
        z.writestr("word/media/image2.png", png, compress_type=zipfile.ZIP_STORED)  # 무압축(시그니처 노출)
    docx = buf.getvalue()
    fmt, eof = engine.identify_carrier_and_eof(docx)
    # 내부 정상 삽입 이미지는 은닉으로 카빙되면 안 됨
    assert engine.carve_embedded_media(docx, fmt, eof) == []
    # 그러나 EOCD 뒤에 결합된 진짜 은닉 PNG는 여전히 포착
    carved = engine.carve_embedded_media(docx + png, fmt, eof)
    assert any("PNG" in c["label"] for c in carved)


def test_chi_square_two_cell_formula():
    """카이제곱: 쌍 평탄(=LSB 치환) 데이터는 은닉가능성↑, 쌍 불균형(정상) 데이터는↓."""
    random.seed(3)
    flat = bytes((random.randint(0, 255) & 0xFE) | random.getrandbits(1) for _ in range(20000))
    p_flat, _, _ = sa.chi_square_lsb(flat)
    skewed = bytes(2 * (b // 2) for b in flat)          # 홀수 빈 제거 → 쌍 극단 불균형
    p_skew, _, _ = sa.chi_square_lsb(skewed)
    assert p_flat > p_skew
    assert p_skew < 0.5


def test_ml_features_tiles_and_calibration():
    """ML 1372차원 특징, 비중첩 타일링(중첩 0%, <256 배제), FPR 구간 선형 보정 검증."""
    from steg_studio import ml
    if not ml.NUMPY_OK:
        return
    import numpy as np
    rng = np.random.default_rng(7)
    g = rng.integers(0, 256, size=(300, 300), dtype=np.uint8)
    f686 = ml.spam_features(g)
    f1372 = ml.extract_features(g, mode="spam686_sca1372")
    assert f686.shape == (686,) and f1372.shape == (1372,)
    assert not np.isnan(f1372).any()

    # 비중첩 타일링: 200x200 -> 0개, 700x700 -> 1개(중첩 없음), 1024x1024 -> 4개
    assert len(ml._extract_tiles(np.zeros((200, 200), dtype=np.uint8))) == 0
    assert len(ml._extract_tiles(np.zeros((700, 700), dtype=np.uint8))) == 1
    assert len(ml._extract_tiles(np.zeros((1024, 1024), dtype=np.uint8))) == 4

    # FPR 보정 매핑: thr_med -> 0.75, thr_high -> 0.90
    assert abs(ml._calibrate_prob(0.60, 0.60, 0.85) - 0.75) < 1e-9
    assert abs(ml._calibrate_prob(0.85, 0.60, 0.85) - 0.90) < 1e-9
    assert ml._calibrate_prob(0.30, 0.60, 0.85) < 0.75
    assert ml._calibrate_prob(0.95, 0.60, 0.85) > 0.90


def test_jpeg_dctr_and_simulators():
    """JPEG ML 경로: 디코더 계수 격자·IDCT 일치, QF 추정, DCTR 8000차원, nsF5/UERD/J-UNIWARD 시뮬레이터."""
    from steg_studio import ml
    if not ml.NUMPY_OK:
        return
    ml._demo_jpeg()


def test_jpeg_skips_spatial_lsb():
    """정상 JPEG 스캔 시 공간(픽셀) LSB/RS/WS 오탐 없이 DCT 분석만 수행되는지."""
    import tempfile
    from steg_studio import engine
    img = _img(seed=11, w=256, h=256)
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tf:
        img.save(tf, "JPEG", quality=85)
        jpath = tf.name
    try:
        res = engine.scan_file(jpath)
        joined_log = "\n".join(res.log_lines)
        assert "JPEG DCT 분석" in joined_log
        assert "RS 분석 추정 은닉률" not in joined_log
    finally:
        if os.path.exists(jpath):
            os.remove(jpath)


def test_v5_packet_roundtrip_and_aad_tamper():
    """v5 AAD 패킷(암호화) 복원 및 헤더 파일명 1바이트 변조 시 무결성 탐지 검증."""
    from steg_studio import crypto
    from steg_studio.constants import LSB_MAGIC
    payload = b"top secret forensic payload 12345"
    pkt = bytearray(crypto.build_packet(LSB_MAGIC, "secret.txt", payload, password="pw123"))
    parsed = crypto.parse_packet(bytes(pkt), LSB_MAGIC, password="pw123")
    assert parsed and parsed["integrity_ok"] and parsed["payload"] == payload
    # 파일명 바이트(offset 11) 1바이트 변조 -> HMAC 실패(wrong_password_or_tampered)
    pkt[11] ^= 0x01
    tampered = crypto.parse_packet(bytes(pkt), LSB_MAGIC, password="pw123")
    assert tampered and tampered.get("wrong_password_or_tampered") is True


def test_cdr_sanitize_clears_eof_and_lsb():
    """CDR 무해화가 PNG 후미 결합 데이터를 제거하고 유효한 이미지를 반환하는지."""
    from steg_studio import engine
    b = io.BytesIO()
    _img(seed=5, w=64, h=64).save(b, "PNG")
    dirty = b.getvalue() + b"__STEG_EOF__TRAILING_PAYLOAD"
    _, eof = engine.identify_carrier_and_eof(dirty)
    clean, _ = engine.cdr_sanitize(dirty, "sample.png", eof)
    _, clean_eof = engine.identify_carrier_and_eof(clean)
    assert clean_eof == len(clean)
    assert b"TRAILING_PAYLOAD" not in clean


def test_pdf_js_reinject_rebuilds_xref():
    """8진수 이스케이프된 PDF /JS 를 수정 재삽입 → 재스캔 시 동일 코드, xref 오프셋 일치."""
    import re
    from steg_studio import engine
    src = (b"%PDF-1.3\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n"
           b"2 0 obj\n<< /S /JavaScript /JS (app\\056alert\\050\\0471\\047\\051) >>\nendobj\n"
           b"3 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n")
    pdf = src + b"xref\n0 4\n" + b"0" * 20 * 4 + b"\ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n"
    off = pdf.index(b"/JS")
    edited = "app.alert('바뀜 (x) \\');".encode()
    out = engine.pdf_reinject_js(pdf, off, edited)
    p = engine.extract_structural_payloads(out, "PDF")[0]
    assert p["data"] == edited
    assert p["decoded"] == edited.decode()   # 편집창에 머리글이 섞이면 재삽입 JS 가 문법 오류가 됨
    for i, o in enumerate(re.findall(rb"(\d{10}) \d{5} n", out), 1):
        assert out[int(o):].startswith(b"%d 0 obj" % i)
    sx = int(re.findall(rb"startxref\s+(\d+)", out)[-1])
    assert out[sx:sx + 4] == b"xref"
    # %%EOF 뒤 후미 은닉 데이터는 JS 재삽입 후에도 보존돼야 함
    hidden = b"\n#include <stdio.h>\nint main(){return 0;}\n"
    assert engine.pdf_reinject_js(pdf + hidden, off, edited).endswith(hidden)


def test_metaedit_png():
    from steg_studio import metaedit
    from PIL.PngImagePlugin import PngInfo
    buf = io.BytesIO(); m = PngInfo(); m.add_text("Software", "OpenStego"); m.add_text("Author", "Spy")
    _img(1, 16, 16).save(buf, "PNG", pnginfo=m)
    data = buf.getvalue()
    clean, _ = metaedit.scrub(data)                       # 삭제
    rows = metaedit.read_metadata(clean)[1]
    assert all("OpenStego" not in v and "Spy" not in v for _, v in rows)
    assert Image.open(io.BytesIO(clean)).size == (16, 16)  # 픽셀 보존
    ed, _ = metaedit.edit(data, {"text:Author": "REDACTED"})   # 편집
    assert any(v == "REDACTED" for _, v in metaedit.read_metadata(ed)[1])


def test_metaedit_jpeg_scrub():
    from steg_studio import metaedit
    buf = io.BytesIO(); img = _img(1, 16, 16); ex = img.getexif(); ex[0x0131] = "TestSoftware"
    img.save(buf, "JPEG", exif=ex)
    sc, _ = metaedit.scrub(buf.getvalue())
    assert all("TestSoftware" not in str(v) for _, v in metaedit.read_metadata(sc)[1])
    assert Image.open(io.BytesIO(sc)).size == (16, 16)


def test_metaedit_pdf():
    from steg_studio import metaedit, engine
    pdf = (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
           b"2 0 obj\n<< /Author (John Smith) /Producer (Acme) >>\nendobj\n"
           b"xref\n0 3\n" + b"0" * 60 + b"\ntrailer\n<< /Size 3 /Root 1 0 R /Info 2 0 R >>\nstartxref\n0\n%%EOF")
    ed, _ = metaedit.edit(pdf, {"Author": "X"})
    assert len(ed) == len(pdf)                             # 길이 보존(xref 안전)
    assert dict(engine.extract_file_metadata(ed)[0]).get("Author") == "X"
    sc, _ = metaedit.scrub(pdf)
    assert len(sc) == len(pdf) and dict(engine.extract_file_metadata(sc)[0]).get("Author", "") == ""


def test_metaedit_ooxml():
    import zipfile
    from steg_studio import metaedit
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("docProps/core.xml", "<cp xmlns:dc='y' xmlns:cp='x'><dc:creator>Alice</dc:creator><dc:title>Doc</dc:title></cp>")
    data = buf.getvalue()
    ed, _ = metaedit.edit(data, {"creator": "Bob"})
    assert dict(metaedit.read_metadata(ed)[1]).get("creator") == "Bob"
    sc, _ = metaedit.scrub(data)
    assert "Alice" not in str(dict(metaedit.read_metadata(sc)[1]))


def test_metaedit_mp3():
    from steg_studio import metaedit, engine
    frame = b"TIT2" + (4).to_bytes(4, "big") + b"\x00\x00" + b"\x03Old"
    sz = len(frame); synch = bytes(((sz >> 21) & 0x7f, (sz >> 14) & 0x7f, (sz >> 7) & 0x7f, sz & 0x7f))
    mp3 = b"ID3\x03\x00\x00" + synch + frame + b"\xff\xfb" + b"\x00" * 50
    ed, _ = metaedit.edit(mp3, {"제목": "New"})
    assert dict(engine.extract_file_metadata(ed)[0]).get("제목") == "New"
    sc, _ = metaedit.scrub(mp3)
    assert sc.startswith(b"\xff\xfb")                      # ID3 제거, 오디오 보존


def test_gps_decimal_decode():
    from steg_studio import engine
    g = {"GPSLatitude": (37, 30, 0), "GPSLatitudeRef": "N", "GPSLongitude": (127, 0, 0), "GPSLongitudeRef": "E"}
    assert engine._gps_decimal(g) == (37.5, 127.0)
    g2 = {"GPSLatitude": (37, 30, 0), "GPSLatitudeRef": "S", "GPSLongitude": (127, 0, 0), "GPSLongitudeRef": "W"}
    assert engine._gps_decimal(g2) == (-37.5, -127.0)


def test_xmp_parse():
    from steg_studio import engine
    xmp = (b'<x:xmpmeta><rdf:RDF><rdf:Description xmp:CreatorTool="Adobe Photoshop" xmpMM:DocumentID="xmp.did:9">'
           b'<dc:creator><rdf:Seq><rdf:li>Alice</rdf:li></rdf:Seq></dc:creator></rdf:Description></rdf:RDF>'
           b'<xmpMM:History>x</xmpMM:History></x:xmpmeta>')
    out = dict(engine._parse_xmp(xmp))
    assert out.get("제작도구(XMP)") == "Adobe Photoshop"
    assert out.get("작성자(XMP)") == "Alice"
    assert "편집이력(XMP)" in out


def test_ooxml_custom_props():
    import zipfile
    from steg_studio import engine
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("docProps/custom.xml",
                   '<Properties><property name="Classification"><vt:lpwstr>SECRET</vt:lpwstr></property></Properties>')
    rows = dict(engine.extract_file_metadata(buf.getvalue())[0])
    assert rows.get("custom:Classification") == "SECRET"


def test_metaedit_png_korean_itxt():
    from steg_studio import metaedit
    buf = io.BytesIO(); _img(1, 16, 16).save(buf, "PNG")
    ed, _ = metaedit.edit(buf.getvalue(), {"Author": "홍길동"})   # latin1 불가 → iTXt(UTF-8)
    assert any(v == "홍길동" for _, v in metaedit.read_metadata(ed)[1])


def test_metaedit_pdf_hex_scrub():
    from steg_studio import metaedit, engine
    pdf = (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
           b"2 0 obj\n<< /Author <4A6F686E> >>\nendobj\n"
           b"xref\n0 3\n" + b"0" * 60 + b"\ntrailer\n<< /Root 1 0 R /Info 2 0 R >>\nstartxref\n0\n%%EOF")
    sc, _ = metaedit.scrub(pdf)
    assert len(sc) == len(pdf)
    assert "John" not in str(dict(engine.extract_file_metadata(sc)[0]).get("Author", ""))


def test_metaedit_ooxml_selfclosing():
    import zipfile
    from steg_studio import metaedit
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:            # 자기닫음 태그 — 정규식이면 실패하던 케이스
        z.writestr("docProps/core.xml", "<cp xmlns:dc='y'><dc:creator/></cp>")
    ed, _ = metaedit.edit(buf.getvalue(), {"creator": "Neo"})
    assert dict(metaedit.read_metadata(ed)[1]).get("creator") == "Neo"


def test_file_metadata_pdf_ooxml():
    from steg_studio import engine
    pdf = b"%PDF-1.4\n1 0 obj\n<< /Title (Secret Report) /Author (Agent) /Producer (OpenStego 0.8) >>\nendobj\n%%EOF"
    d = dict(engine.extract_file_metadata(pdf)[0])
    assert d.get("Title") == "Secret Report" and d.get("Author") == "Agent"
    assert any("스테가" in a for a in engine.extract_file_metadata(pdf)[1])   # Producer=OpenStego → 경보
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("docProps/core.xml", "<cp><dc:creator>김철수</dc:creator><dc:title>보고서</dc:title></cp>")
    d2 = dict(engine.extract_file_metadata(buf.getvalue())[0])
    assert d2.get("creator") == "김철수" and d2.get("title") == "보고서"


def test_obfuscated_blob_heuristic():
    from steg_studio import engine
    blob = ("[0&6:^+8&+3<9k;:0>}(},=$#@!%*/-ABxYz" * 4000).encode()   # 긴 단일라인·공백없음·제한알파벳(~30종)
    assert engine.obfuscated_blob_score(blob)[0]
    normal = ("The quick brown fox jumps over the lazy dog.\n" * 500).encode()
    assert not engine.obfuscated_blob_score(normal)[0]     # 자연어는 공백·개행 많아 제외


def test_image_metadata_extraction():
    # EXIF/텍스트 메타 추출 + 스테가 도구 흔적 경보
    from steg_studio import engine
    from PIL.PngImagePlugin import PngInfo
    buf = io.BytesIO()
    meta = PngInfo()
    meta.add_text("Software", "OpenStego v0.8")
    meta.add_text("Comment", "hello")
    _img(3, 32, 32).save(buf, "PNG", pnginfo=meta)
    rows, alerts = engine.extract_image_metadata(Image.open(io.BytesIO(buf.getvalue())))
    keys = [k for k, _ in rows]
    assert any("Software" in k for k in keys)
    assert any("스테가" in a for a in alerts)


def test_effective_ext_sniffs_disguised():
    # 픽셀/오디오/비디오 분기가 '내용' 기반이어야 함 — 위장 확장자(.unknown)로 스테가분석 우회 방지
    from steg_studio import engine
    png = io.BytesIO(); _img(2, 64, 64).save(png, "PNG")
    assert engine._effective_ext(png.getvalue(), "/x/y.unknown") == ".png"
    assert engine._effective_ext(b"\xff\xd8\xff\xe0rest", "/x/z.bin") == ".jpg"
    assert engine._effective_ext(b"BM" + b"\x00" * 20, "/x/w") == ".bmp"
    # 매칭 없으면 파일명 확장자로 폴백
    assert engine._effective_ext(b"nomagic", "/x/a.png") == ".png"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("OK", name)


# ---------------- 메타데이터 강화 회귀 테스트 ----------------
def test_metaedit_jpeg_lossless_edit_and_color_kept():
    """EXIF 편집은 압축 데이터 그대로(무손실), 스크럽은 ICC(APP2)·Adobe(APP14) 유지, GPS·일련번호 삭제 가능."""
    from steg_studio import metaedit
    img = _img(2, 32, 32); ex = img.getexif(); ex[0x0131] = "Cam"
    ex.get_ifd(0x8769)[0xA431] = "SN123"
    ex.get_ifd(0x8825).update({1: "N", 2: (37.0, 30.0, 0.0), 3: "E", 4: (127.0, 0.0, 0.0)})
    buf = io.BytesIO(); img.save(buf, "JPEG", exif=ex, icc_profile=b"\x00" * 200)
    data = buf.getvalue()
    sos = data.index(b"\xff\xda")
    ed, info = metaedit.edit(data, {"Software": "X", "본체일련번호": "", "GPS 좌표": "", "없는키": "1"})
    rows = dict(metaedit.read_metadata(ed)[1])
    assert rows.get("Software") == "X" and "본체일련번호" not in rows and "GPS 좌표" not in rows
    assert ed.endswith(data[sos:])                          # 압축 스트림 바이트 동일 = 재인코딩 없음
    assert "없는키" in info                                  # 적용 못 한 키는 알림
    sc, info = metaedit.scrub(data)
    assert b"ICC_PROFILE" in sc and b"Exif" not in sc and "잔존 없음" in info


def test_metaedit_pdf_incremental_and_xmp():
    """증분 업데이트로 /Info가 두 번 있으면 둘 다 수정/삭제, 비압축 XMP도 스크럽."""
    from steg_studio import metaedit, engine
    pdf = (b"%PDF-1.4\n2 0 obj\n<< /Author (Alice Old) >>\nendobj\n"
           b"3 0 obj\n<< /Type /Metadata /Length 80 >>\nstream\n"
           b"<x:xmpmeta><dc:creator><rdf:Seq><rdf:li>Alice</rdf:li></rdf:Seq></dc:creator></x:xmpmeta>\nendstream\nendobj\n"
           b"%%EOF\n2 0 obj\n<< /Author (Alice New) >>\nendobj\n%%EOF")
    ed, _ = metaedit.edit(pdf, {"Author": "Bob"})
    assert len(ed) == len(pdf) and b"Alice Old" not in ed and b"Alice New" not in ed
    sc, info = metaedit.scrub(pdf)
    assert len(sc) == len(pdf) and b"Alice" not in sc and "XMP" in info
    _, trunc, _, _ = metaedit._pdf_update(b"/Author (ab)", {"Author": "a(("})   # 잘린 이스케이프로 ')' 먹힘 방지
    assert trunc == ["Author"]
    assert dict(engine.extract_file_metadata(b"%PDF-1.4 /Author <FEFF00410042>")[0])["Author"] == "AB"


def test_metaedit_ooxml_custom_comments_times():
    import zipfile
    from steg_studio import metaedit
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("docProps/custom.xml", (2024, 5, 5, 1, 2, 4)),
                   '<Properties><property name="Owner"><vt:lpwstr xmlns:vt="v">Alice</vt:lpwstr></property></Properties>')
        z.writestr("word/comments.xml", '<w:comments xmlns:w="w"><w:comment w:author="Alice" w:initials="AL"/></w:comments>')
    data = buf.getvalue()
    ed, _ = metaedit.edit(data, {"custom:Owner": "Bob"})
    assert dict(metaedit.read_metadata(ed)[1]).get("custom:Owner") == "Bob"
    sc, info = metaedit.scrub(data)
    z = zipfile.ZipFile(io.BytesIO(sc))
    assert b"Alice" not in z.read("word/comments.xml") and b"Alice" not in z.read("docProps/custom.xml")
    assert all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in z.infolist())
    assert "잔존 없음" in info


def test_metaedit_mp3_v24_and_ape():
    """ID3v2.4(synchsafe 프레임 크기) 편집 시 버전·APIC 보존, 스크럽은 APE 태그까지 제거."""
    from steg_studio import metaedit, engine
    ss = lambda n: bytes(((n >> 21) & 0x7f, (n >> 14) & 0x7f, (n >> 7) & 0x7f, n & 0x7f))
    title = b"\x03" + "제목".encode() + b"x" * 130                     # 128B 초과 → synchsafe 차이 발생
    fr = b"TIT2" + ss(len(title)) + b"\x00\x00" + title + b"APIC" + ss(5) + b"\x00\x00" + b"\x00img\x00"
    audio = b"\xff\xfb" + b"\x00" * 50
    ape = b"APETAGEX" + (2000).to_bytes(4, "little") + (32).to_bytes(4, "little") + bytes(4) + bytes(4) + bytes(8)
    mp3 = b"ID3\x04\x00\x00" + ss(len(fr)) + fr + audio + ape
    assert dict(engine.extract_file_metadata(mp3)[0])["제목"].startswith("제목x")
    ed, _ = metaedit.edit(mp3, {"제목": "새 제목", "코멘트": "메모"})
    d = dict(engine.extract_file_metadata(ed)[0])
    assert ed[3] == 4 and d["제목"] == "새 제목" and d["코멘트"] == "메모"
    assert any(f == b"APIC" for f, _, _ in engine.id3_frames(ed)[2])
    sc, _ = metaedit.scrub(mp3)
    assert sc == audio


def test_metaedit_mp4_size_preserved_and_heif_rejected():
    """udta/meta는 같은 크기 free로 → 파일 크기·stco 오프셋 불변. mvhd 시각 0. HEIC는 거부."""
    from steg_studio import metaedit, engine
    box = lambda t, p: struct.pack(">I", 8 + len(p)) + t + p
    mvhd = box(b"mvhd", b"\x00\x00\x00\x00" + (3_000_000_000).to_bytes(4, "big") * 2 + bytes(88))
    udta = box(b"udta", box(b"\xa9too", box(b"data", bytes(8) + b"SecretCam v1")))
    mp4 = box(b"ftyp", b"isom" + bytes(4)) + box(b"moov", mvhd + udta) + box(b"mdat", b"\x01" * 20)
    sc, info = metaedit.scrub(mp4)
    assert len(sc) == len(mp4) and b"SecretCam" not in sc and sc.endswith(box(b"mdat", b"\x01" * 20))
    assert (3_000_000_000).to_bytes(4, "big") not in sc and "잔존 없음" in info
    heic = box(b"ftyp", b"heic" + bytes(4)) + box(b"meta", bytes(20))
    assert metaedit.detect_format(heic) == "heif"   # MP4로 오인하지 않고 HEIF 전용 처리


# ---------------- 메타데이터 2차 강화: 잔존 검사·HWPX·포렌식·pikepdf·신규 포맷 ----------------
def test_metaedit_leak_check_catches_unknown_location():
    """리더가 모르는 파트(customXml)에 남은 원본 값을 '잔존'으로 잡아야 함 — '잔여 없음' 오판 방지."""
    import zipfile
    from steg_studio import metaedit
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("docProps/core.xml", "<cp xmlns:dc='y'><dc:creator>Alice Kimberly</dc:creator></cp>")
        z.writestr("customXml/item1.xml", "<x><owner>Alice Kimberly</owner></x>")   # 압축돼 있어도 찾아야 함
    _, info = metaedit.scrub(buf.getvalue())
    assert "원본 값이 파일 안에 잔존" in info and "creator" in info


def test_metaedit_hwpx():
    import zipfile
    from steg_studio import metaedit, engine
    hpf = ('<opf:package xmlns:opf="http://www.idpf.org/2007/opf/"><opf:metadata>'
           '<opf:title>기밀 보고서</opf:title><opf:language>ko</opf:language>'
           '<opf:meta name="creator" content="text">홍길동</opf:meta>'
           '<opf:meta name="lastsaveby" content="text">김철수</opf:meta>'
           '<opf:meta name="CreatedDate" content="text">2025-03-01T09:00:00Z</opf:meta>'
           '<opf:meta name="ModifiedDate" content="text">2024-01-01T09:00:00Z</opf:meta>'
           '</opf:metadata></opf:package>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("mimetype", "application/hwp+zip")
        z.writestr("Contents/content.hpf", hpf)
    data = buf.getvalue()
    assert metaedit.detect_format(data) == "hwpx"
    rows, alerts = engine.extract_file_metadata(data)
    assert dict(rows)["hwpx:creator"] == "홍길동" and any("시각 조작" in a for a in alerts)   # 수정일 < 작성일
    ed, _ = metaedit.edit(data, {"hwpx:lastsaveby": "익명"})
    assert dict(metaedit.read_metadata(ed)[1])["hwpx:lastsaveby"] == "익명"
    sc, info = metaedit.scrub(data)
    assert not metaedit.read_metadata(sc)[1] and "잔존 없음" in info
    assert zipfile.ZipFile(io.BytesIO(sc)).namelist()[0] == "mimetype"    # HWPX 규격: mimetype이 첫 엔트리


def _jpeg_with_thumb(main, thumb, dt=None, shot=None):
    """IFD0(+선택 DateTime/ExifIFD) + IFD1 썸네일을 가진 EXIF APP1을 손으로 조립해 JPEG에 삽입."""
    tb = io.BytesIO(); thumb.save(tb, "JPEG"); tb = tb.getvalue()
    ex = Image.Exif()
    ex[0x0131] = "Cam"
    if dt:
        ex[0x0132] = dt
    if shot:
        ex.get_ifd(0x8769)[0x9003] = shot
    tiff = bytearray(ex.tobytes()[6:])
    e = "<" if tiff[:2] == b"II" else ">"
    # IFD0의 next-IFD 포인터를 끝에 붙일 IFD1로 연결
    ifd0 = struct.unpack(e + "I", tiff[4:8])[0]
    n0 = struct.unpack(e + "H", tiff[ifd0:ifd0 + 2])[0]
    ifd1 = len(tiff)
    tiff[ifd0 + 2 + 12 * n0:ifd0 + 6 + 12 * n0] = struct.pack(e + "I", ifd1)
    thumb_off = ifd1 + 2 + 2 * 12 + 4
    tiff += struct.pack(e + "H", 2) + struct.pack(e + "HHII", 0x0201, 4, 1, thumb_off) \
        + struct.pack(e + "HHII", 0x0202, 4, 1, len(tb)) + b"\x00" * 4 + tb
    mb = io.BytesIO(); main.save(mb, "JPEG", quality=95); mb = mb.getvalue()
    app1 = b"Exif\x00\x00" + bytes(tiff)
    return mb[:2] + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + mb[2:]


def test_forensics_thumbnail_and_dates():
    from steg_studio import engine
    main = Image.new("L", (160, 120), 200); main.paste(30, (80, 0, 160, 120))
    same = main.resize((80, 60))
    other = Image.new("L", (80, 60), 30); other.paste(200, (40, 0, 80, 60))   # 좌우 반전 = 편집됨
    ok = Image.open(io.BytesIO(_jpeg_with_thumb(main, same)))
    assert not engine.thumbnail_mismatch(ok)                                    # 정상: 경보 없음
    bad = Image.open(io.BytesIO(_jpeg_with_thumb(main, other, dt="2024:01:01 00:00:00", shot="2024:06:01 12:00:00")))
    alerts = engine.extract_image_metadata(bad)[1]
    assert any("썸네일" in a for a in alerts) and any("시각 조작" in a for a in alerts)


def test_forensics_pdf_and_zip():
    import zipfile
    from steg_studio import engine
    pdf = (b"%PDF-1.4\n1 0 obj\n<< /Producer (Word) /CreationDate (D:20240601) /ModDate (D:20240601) >>\nendobj\n"
           b"startxref\n0\n%%EOF\n1 0 obj\n<< /Producer (PDFEdit Pro) /CreationDate (D:20240601) /ModDate (D:20230101) >>\nendobj\n"
           b"startxref\n0\n%%EOF\n")
    a = engine.extract_file_metadata(pdf)[1]
    assert any("증분 업데이트 1회" in x for x in a) and any("Producer가 다름" in x for x in a)
    assert any("시각 조작" in x for x in a)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in ("[Content_Types].xml", "word/document.xml", "docProps/core.xml"):
            z.writestr(zipfile.ZipInfo(n, (1980, 1, 1, 0, 0, 0)), "<x/>")
        z.writestr(zipfile.ZipInfo("word/vbaProject.bin", (2025, 5, 5, 3, 3, 4)), "x")   # 나중에 끼워넣은 파트
    assert any("vbaProject" in x for x in engine.extract_file_metadata(buf.getvalue())[1])


def test_metaedit_pdf_pikepdf_rewrite():
    """pikepdf 있으면: 압축 XMP까지 읽고, 스크럽은 전체 재작성으로 증분 업데이트 이전 판(옛 작성자)까지 제거."""
    import re
    pikepdf = __import__("pytest").importorskip("pikepdf")
    from steg_studio import metaedit, engine
    pdf = pikepdf.new(); pdf.add_blank_page()
    pdf.docinfo["/Author"] = "Alice New"
    pdf.Root.Metadata = pdf.make_stream(b'<x:xmpmeta><rdf:Description xmp:CreatorTool="SecretTool 9"/></x:xmpmeta>')
    b = io.BytesIO(); pdf.save(b, compress_streams=True, fix_metadata_version=False); base = b.getvalue()
    assert b"SecretTool" not in base                                    # XMP가 압축돼 정규식으론 안 보이는 상황
    # 증분 업데이트 흉내: 이전 판 객체(옛 작성자)를 뒤에 덧붙임 — 어디서도 참조 안 됨
    root = re.search(rb"/Root (\d+ \d+ R)", base).group(1)
    prev = re.findall(rb"startxref\s+(\d+)", base)[-1]
    obj_off = len(base)
    body = b"99 0 obj\n<< /Author (Alice Old) >>\nendobj\n"
    xref_off = obj_off + len(body)
    pdf2 = base + body + b"xref\n99 1\n%010d 00000 n \ntrailer\n<< /Size 100 /Root %s /Prev %s >>\nstartxref\n%d\n%%%%EOF\n" % (
        obj_off, root, prev, xref_off)
    rows = dict(engine.extract_file_metadata(pdf2)[0])
    assert rows.get("제작도구(XMP)") == "SecretTool 9"                  # pikepdf가 압축 XMP를 읽어냄
    sc, info = metaedit.scrub(pdf2)
    assert b"Alice" not in sc and b"SecretTool" not in metaedit._haystack(sc)
    assert "pikepdf" in info and "이전 판 1개" in info and "잔존 없음" in info
    ed, _ = metaedit.edit(pdf2, {"Author": "아주 긴 새 작성자 이름 — 길이 제한 없음"})
    assert dict(engine.extract_file_metadata(ed)[0])["Author"].startswith("아주 긴")


def _heic(exif_tiff, xmp):
    """최소 HEIF: ftyp(heic) + meta(iinf: Exif, mime XMP / iloc) + mdat."""
    box = lambda t, p: struct.pack(">I", 8 + len(p)) + t + p
    full = lambda t, v, p: box(t, bytes([v, 0, 0, 0]) + p)
    exif_item = b"\x00\x00\x00\x06" + exif_tiff                      # 앞 4B=TIFF까지 오프셋(=Exif\0\0 6B)
    infe1 = full(b"infe", 2, struct.pack(">HH", 1, 0) + b"Exif" + b"\x00")
    infe2 = full(b"infe", 2, struct.pack(">HH", 2, 0) + b"mime" + b"\x00" + b"application/rdf+xml\x00")
    iinf = full(b"iinf", 0, struct.pack(">H", 2) + infe1 + infe2)

    def build(off1, off2):
        iloc = full(b"iloc", 0, bytes([0x44, 0x00]) + struct.pack(">H", 2)
                    + struct.pack(">HHHII", 1, 0, 1, off1, len(exif_item))
                    + struct.pack(">HHHII", 2, 0, 1, off2, len(xmp)))
        return box(b"ftyp", b"heic" + bytes(4) + b"mif1heic") + full(b"meta", 0, iinf + iloc)
    start = len(build(0, 0)) + 8
    return build(start, start + len(exif_item)) + box(b"mdat", exif_item + xmp)


def test_metaedit_heic():
    from steg_studio import metaedit
    ex = Image.Exif(); ex[0x0131] = "iPhone 15 Pro"
    ex.get_ifd(0x8825).update({1: "N", 2: (37.0, 33.0, 0.0), 3: "E", 4: (126.0, 58.0, 0.0)})
    heic = _heic(ex.tobytes(), b'<x:xmpmeta><rdf:Description xmp:CreatorTool="Photos 9"/></x:xmpmeta>')
    fmt, rows = metaedit.read_metadata(heic)
    d = dict(rows)
    assert fmt.startswith("HEIC") and d["Software"] == "iPhone 15 Pro" and "GPS 좌표" in d and "제작도구(XMP)" in d
    sc, info = metaedit.scrub(heic)
    assert len(sc) == len(heic) and not metaedit.read_metadata(sc)[1] and "잔존 없음" in info


def test_metaedit_webp_wav_tiff():
    import wave
    from steg_studio import metaedit
    img = _img(3, 32, 32)
    # WebP: EXIF + XMP → 제거, 픽셀 무손실
    ex = Image.Exif(); ex[0x013B] = "Alice Artist"
    b = io.BytesIO(); img.save(b, "WEBP", lossless=True, exif=ex.tobytes(), xmp=b"<x:xmpmeta>Alice</x:xmpmeta>")
    sc, info = metaedit.scrub(b.getvalue())
    assert b"Alice" not in sc and "잔존 없음" in info
    assert Image.open(io.BytesIO(sc)).convert("RGB").tobytes() == img.convert("RGB").tobytes()
    # WAV: LIST/INFO + bext → 제거, 오디오 그대로
    b = io.BytesIO()
    with wave.open(b, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000); w.writeframes(b"\x01\x02" * 100)
    info_list = b"INFO" + b"INAM" + (6).to_bytes(4, "little") + b"Memo\x00\x00" + b"IART" + (6).to_bytes(4, "little") + b"Alice\x00"
    bext = b"bext" + (602).to_bytes(4, "little") + b"Interview".ljust(256, b"\x00") + b"ZOOM H5".ljust(32, b"\x00") + bytes(314)
    wav = b.getvalue() + b"LIST" + len(info_list).to_bytes(4, "little") + info_list + bext
    wav = wav[:4] + (len(wav) - 8).to_bytes(4, "little") + wav[8:]
    d = dict(metaedit.read_metadata(wav)[1])
    assert d["아티스트"] == "Alice" and d["BWF 녹음장비"] == "ZOOM H5"
    sc, info = metaedit.scrub(wav)
    assert b"Alice" not in sc and b"ZOOM" not in sc and "잔존 없음" in info
    with wave.open(io.BytesIO(sc)) as w:
        assert w.readframes(100) == b"\x01\x02" * 100
    # TIFF: Artist/Software → 제거, 같은 압축으로 픽셀 무손실
    b = io.BytesIO(); img.save(b, "TIFF", compression="tiff_lzw", tiffinfo={315: "Alice Artist", 305: "SecretSoft"})
    d = dict(metaedit.read_metadata(b.getvalue())[1])
    assert d.get("Artist") == "Alice Artist" and "StripOffsets" not in d                # 구조 태그는 숨김
    sc, info = metaedit.scrub(b.getvalue())
    assert b"Alice" not in sc and b"SecretSoft" not in sc and "잔존 없음" in info
    assert Image.open(io.BytesIO(sc)).tobytes() == img.tobytes()


def test_png_private_chunk_and_mp4_gps():
    from steg_studio import metaedit, engine
    b = io.BytesIO(); _img(4, 16, 16).save(b, "PNG"); d = b.getvalue()
    priv = metaedit._png_chunk(b"prVt", b"hidden payload")                     # 비표준 private 청크
    d = d[:-12] + priv + d[-12:]
    sc, _ = metaedit.scrub(d)
    assert b"hidden payload" not in sc and Image.open(io.BytesIO(sc)).size == (16, 16)
    box = lambda t, p: struct.pack(">I", 8 + len(p)) + t + p
    mp4 = box(b"ftyp", b"isom" + bytes(4)) + box(b"moov", box(b"udta", box(b"\xa9xyz", b"\x00\x11\x15\xc7+37.5665+126.9780/")))
    rows, alerts = engine.extract_file_metadata(mp4)
    assert dict(rows)["촬영 위치(GPS)"] == "+37.5665+126.9780/" and any("GPS" in a for a in alerts)
    assert "잔존 없음" in metaedit.scrub(mp4)[1]


# ---------------- 공격 전달 포맷 (RTF / LNK / ISO) — 무해한 합성 샘플 ----------------
def _lnk(target=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         args="-w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAB0AGUAcwB0AA==",
         icon=r"C:\Windows\System32\imageres.dll", show=7, tail=b""):
    """바로가기 바이너리 합성 (명령은 'Write-Output test' — 무해)."""
    flags = 0x8 | 0x20 | 0x40 | 0x80            # RelativePath | Arguments | IconLocation | Unicode
    hdr = struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000c000000000000046") + struct.pack("<I", flags)
    hdr += bytes(0x3C - len(hdr)) + struct.pack("<I", show)
    hdr += bytes(76 - len(hdr))
    sd = b"".join(struct.pack("<H", len(s)) + s.encode("utf-16-le") for s in (target, args, icon))
    return hdr + sd + b"\x00\x00\x00\x00" + tail


def _iso(files):
    """최소 ISO 9660 합성. files = [(이름, 데이터, 숨김)]."""
    def rec(name, extent, size, flags):
        pad = b"\x00" if len(name) % 2 == 0 else b""
        rl = 33 + len(name) + len(pad)
        return (bytes([rl, 0]) + struct.pack("<I", extent) + struct.pack(">I", extent)
                + struct.pack("<I", size) + struct.pack(">I", size) + bytes(7) + bytes([flags, 0, 0])
                + struct.pack("<H", 1) + struct.pack(">H", 1) + bytes([len(name)]) + name + pad)
    root = rec(b"\x00", 18, 2048, 2) + rec(b"\x01", 18, 2048, 2)
    for i, (name, data, hidden) in enumerate(files):
        root += rec(name.encode() + b";1", 19 + i, len(data), 1 if hidden else 0)
    total = 19 + len(files)
    pvd = bytearray(2048)
    pvd[0:7] = b"\x01CD001\x01"
    pvd[80:88] = struct.pack("<I", total) + struct.pack(">I", total)
    pvd[128:132] = struct.pack("<H", 2048) + struct.pack(">H", 2048)
    pvd[156:190] = rec(b"\x00", 18, 2048, 2)
    term = b"\xffCD001\x01" + bytes(2041)
    body = bytes(16 * 2048) + bytes(pvd) + term + root.ljust(2048, b"\x00")
    for _, data, _ in files:
        body += data.ljust(-(-len(data) // 2048) * 2048, b"\x00")
    return body


def test_delivery_lnk():
    from steg_studio import delivery
    d = _lnk(tail=b"APPENDED-PAYLOAD" * 4)
    fmt, eof = delivery.identify(d)
    assert fmt == "LNK 바로가기" and eof == len(d) - 64            # 덧붙인 데이터 직전이 정상 종료
    _, threats, payloads = delivery.inspect(d)
    msgs = " | ".join(m for _, m in threats)
    for want in ("powershell", "-enc", "-WindowStyle Hidden", "SW_SHOWMINNOACTIVE", "아이콘 위장"):
        assert want in msgs, (want, msgs)
    assert payloads and "powershell.exe -w hidden" in payloads[0]["decoded"]
    # 평범한 문서 바로가기는 경보 없음
    _, t2, _ = delivery.inspect(_lnk(target=r"C:\Users\a\report.docx", args="", icon="", show=1))
    assert not t2, t2


def test_delivery_rtf():
    from steg_studio import delivery
    def ole1(cls, native):
        c = cls.encode() + b"\x00"
        return (struct.pack("<II", 0x0501, 2) + struct.pack("<I", len(c)) + c
                + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<I", len(native)) + native)
    exe = b"MZ" + bytes(62)
    pkg = (b"\x02\x00" + b"invoice.pdf.exe\x00" + rb"C:\tmp\invoice.pdf.exe" + b"\x00" + b"\x00\x00\x03\x00"
           + struct.pack("<I", 4) + b"C:" + bytes([0x5C, 0]) + struct.pack("<I", len(exe)) + exe)
    hexify = lambda b: r" \par ".join(b.hex()[i:i + 40] for i in range(0, len(b.hex()), 40)).encode()  # 제어어 끼워 난독화
    rtf = (rb"{\rtf1{\*\template http://example.test/t.dotm}"
           rb"{\object\objemb\objupdate{\*\objclass Equation.3}{\*\objdata " + hexify(ole1("Equation.3", b"\x1c" * 32)) + b"}}"
           rb"{\object\objemb{\*\objclass Package}{\*\objdata " + hexify(ole1("Package", pkg)) + b"}}}")
    assert delivery.identify(rtf) == ("RTF 문서", len(rtf))
    _, threats, payloads = delivery.inspect(rtf)
    grades = {m: g for g, m in threats}
    assert any("CVE-2017-11882" in m and g == "CRITICAL" for m, g in grades.items()), threats
    assert any("objupdate" in m for m in grades) and any("원격 템플릿" in m for m in grades)
    assert any("invoice.pdf.exe" in m and g == "HIGH" for m, g in grades.items()), threats
    assert any(p["name"] == "invoice.pdf.exe" and p["data"] == exe for p in payloads)


def test_delivery_iso_and_engine_recursion():
    import tempfile
    from steg_studio import delivery, engine
    iso = _iso([("REPORT.LNK", _lnk(), False), ("PAYLOAD.DLL", b"MZ" + bytes(500), True)])
    fmt, eof = delivery.identify(iso)
    assert fmt == "ISO/IMG 디스크 이미지" and eof == len(iso)
    _, threats, payloads = delivery.inspect(iso)
    assert any(g == "CRITICAL" and "숨김" in m for g, m in threats), threats
    assert {p["name"] for p in payloads} == {"REPORT.LNK", "PAYLOAD.DLL"}
    # 엔진 전체: ISO → (추출) LNK → (재귀) 바로가기 명령 분석까지 연결
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "delivery.iso")
        with open(p, "wb") as f:
            f.write(iso)
        r = engine.scan_file(p)
    joined = " | ".join(r.findings)
    assert "[전달포맷/CRITICAL]" in joined and "REPORT.LNK 내부" in joined and "powershell" in joined, joined
    assert engine._verdict(r)[0] == "의심"


# ---------------- 압축·디스크 이미지 내부 파일 정밀 스캔 ----------------
def _zip_bytes(entries, comp=None):
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", comp or zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


def _scan_bytes(data, name):
    import tempfile
    from steg_studio import engine
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, name)
        with open(p, "wb") as f:
            f.write(data)
        return engine.scan_file(p)


def _stego_png():
    """기존 은닉 기능으로 무해한 페이로드(print('hi'))를 숨긴 PNG."""
    import tempfile
    from steg_studio import embed
    with tempfile.TemporaryDirectory() as td:
        carrier = os.path.join(td, "c.png")
        _img(5, 160, 120).save(carrier)
        out, _, _ = embed.embed_pixelcode_lsb(carrier, "hi.py", b"print('hi')\n")
    return out


def test_archive_member_stego_detected():
    """ZIP·ISO 안의 스테가 이미지도 단독 스캔과 같은 픽셀 LSB 분석을 받아야 한다(과거: 정상으로 누락)."""
    from steg_studio import engine
    png = _stego_png()
    for zname, data in (("deflate.zip", _zip_bytes([("photos/a.png", png), ("readme.txt", b"hello")])),
                        ("iso.iso", _iso([("A.PNG", png, False)]))):
        r = _scan_bytes(data, zname)
        joined = " | ".join(r.findings)
        assert engine._verdict(r)[0] == "의심", (zname, joined)
        assert "[내부:" in joined and "픽셀 LSB" in joined, (zname, joined)
        assert any(it.name == "hi.py" for it in r.carved), zname       # 숨긴 파일 복원까지
    # 중첩: ZIP 안 ZIP(깊이 2)까지는 검사, 3단계부터는 상한으로 생략
    inner = _zip_bytes([("a.png", png)])
    assert "픽셀 LSB" in " ".join(_scan_bytes(_zip_bytes([("in.zip", inner)]), "n2.zip").findings)
    deep = _scan_bytes(_zip_bytes([("l1.zip", _zip_bytes([("l2.zip", inner)]))]), "n3.zip")
    assert "픽셀 LSB" not in " ".join(deep.findings)
    assert any("중첩 깊이 상한" in f and "MEDIUM" in f for f in deep.findings), deep.findings   # 생략 사실은 경보로 보임


def test_archive_member_clean_and_bomb_guard():
    from steg_studio import engine
    clean = _scan_bytes(_zip_bytes([("notes.txt", b"meeting at 3pm\n" * 50)]), "clean.zip")
    assert engine._verdict(clean)[0] == "정상", clean.findings
    # 압축 폭탄형(해제 시 상한 초과) 항목은 해제하지 않고 건너뜀
    bomb = _scan_bytes(_zip_bytes([("zeros.bin", bytes(engine.ARCHIVE_MAX_MEMBER + 1))]), "bomb.zip")
    assert any("크기 상한" in l for l in bomb.log_lines)
