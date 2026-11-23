"""
컨테이너 내부 구조 검사 — 정상 파서는 무시하지만 데이터를 숨길 수 있는 '틈새'를 찾는다.

- PNG: IDAT zlib 스트림 뒤 잔여 바이트, 이미지 크기보다 많이 풀리는 데이터, 잘못된 필터 바이트,
       IDAT 사이에 끼운 청크, 표준 인코더로 재현되지 않는 압축(참고용).
- MP4/MOV: 트랙이 참조하지 않는 mdat 영역, 0이 아닌 free/skip 박스, uuid/비표준 최상위 박스.
GUI 비의존 순수 함수. 반환 형식: (리포트 줄 목록, 위협 [(등급, 메시지)], 추출 페이로드 [dict])
"""

import struct
import zlib


# =========================================================================
# PNG
# =========================================================================
_PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
_ADAM7 = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2))


def _png_raw_size(w, h, depth, ctype, interlace):
    """필터 바이트 포함, 정상적으로 풀려야 하는 IDAT 데이터 크기."""
    bpp_bits = _PNG_CHANNELS.get(ctype, 1) * depth
    if not interlace:
        return h * (1 + (w * bpp_bits + 7) // 8)
    total = 0
    for x0, y0, dx, dy in _ADAM7:
        pw = (w - x0 + dx - 1) // dx if w > x0 else 0
        ph = (h - y0 + dy - 1) // dy if h > y0 else 0
        if pw and ph:
            total += ph * (1 + (pw * bpp_bits + 7) // 8)
    return total


def inspect_png(data):
    lines, threats, payloads = [], [], []
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return lines, threats, payloads
    pos, ihdr, idat, idat_runs, last = 8, None, bytearray(), 0, None
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        if ctype == b"IHDR" and len(body) >= 13:
            ihdr = struct.unpack(">IIBBBBB", body[:13])
        elif ctype == b"IDAT":
            if last != b"IDAT":
                idat_runs += 1
            idat += body
        last = ctype
        pos += 12 + length
        if ctype == b"IEND":
            break
    if not ihdr or not idat:
        return lines, threats, payloads
    w, h, depth, ctype_, _, _, interlace = ihdr
    expected = _png_raw_size(w, h, depth, ctype_, interlace)
    lines.append(f" • PNG IDAT: 압축 {len(idat):,} B, IDAT 연속 구간 {idat_runs}개, 기대 원본 {expected:,} B")

    if idat_runs > 1:
        threats.append(("MEDIUM", f"IDAT 청크 사이에 다른 청크가 끼어 있음({idat_runs}구간) — 표준 위반, 은닉 의심"))

    d = zlib.decompressobj()
    try:
        raw = d.decompress(bytes(idat), expected + 1024 * 1024)
        raw += d.flush()
    except zlib.error as e:
        threats.append(("MEDIUM", f"IDAT zlib 스트림 손상: {e}"))
        return lines, threats, payloads
    if d.unused_data:
        threats.append(("HIGH", f"IDAT zlib 스트림 종료 뒤 잔여 {len(d.unused_data):,} B — 압축 스트림 뒤 은닉"))
        payloads.append({"category": "PNG IDAT 잔여", "fmt": "zlib 뒤 잔여 데이터", "offset": "IDAT",
                         "data": bytes(d.unused_data), "detail": "IDAT zlib 스트림 종료 뒤 덧붙은 데이터",
                         "name": "idat_trailing.bin"})
    if len(raw) > expected:
        extra = raw[expected:]
        threats.append(("HIGH", f"IDAT가 이미지 크기보다 {len(extra):,} B 더 풀림 — 압축 데이터 내부 은닉"))
        payloads.append({"category": "PNG IDAT 초과", "fmt": "초과 해제 데이터", "offset": f"IDAT+{expected}",
                         "data": bytes(extra), "detail": f"기대 {expected:,} B 이후 추가 해제된 데이터",
                         "name": "idat_extra.bin"})
    elif len(raw) < expected:
        lines.append(f"   - 해제 크기 부족({len(raw):,} B) — 잘린 파일일 수 있음")

    if not interlace and len(raw) >= expected:
        stride = 1 + (w * _PNG_CHANNELS.get(ctype_, 1) * depth + 7) // 8
        bad = sum(1 for y in range(h) if raw[y * stride] > 4)
        if bad:
            threats.append(("MEDIUM", f"잘못된 필터 바이트 {bad}행 — 필터 바이트 자리에 데이터 은닉 의심"))

    # 표준 zlib 레벨로 재현되는지(참고) — 최적화 도구(zopfli 등)는 불일치가 정상이라 위협으로 보지 않음
    comp = raw[:expected]
    if any(zlib.compress(comp, lv) == bytes(idat[:len(idat) - len(d.unused_data)]) for lv in range(10)):
        lines.append("   - 압축: 표준 zlib 레벨로 정확히 재현됨")
    else:
        lines.append("   - 압축: 표준 zlib 레벨과 불일치(최적화 도구/타 인코더면 정상, 참고용)")
    return lines, threats, payloads


# =========================================================================
# MP4 / MOV (ISO BMFF)
# =========================================================================
_TOP_KNOWN = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta", b"pdin",
              b"styp", b"sidx", b"moof", b"mfra", b"emsg", b"prft", b"ssix"}
_CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"dinf", b"udta", b"mvex"}


def _boxes(data, start, end):
    pos = start
    while pos + 8 <= end:
        size, typ = struct.unpack(">I4s", data[pos:pos + 8])
        hdr = 8
        if size == 1 and pos + 16 <= end:
            size = struct.unpack(">Q", data[pos + 8:pos + 16])[0]
            hdr = 16
        elif size == 0:
            size = end - pos
        if size < hdr or pos + size > end:
            yield pos, typ, hdr, end - pos, True        # 잘못된 크기
            return
        yield pos, typ, hdr, size, False
        pos += size


def _sample_bytes(data, start, end):
    """moov 아래 모든 트랙의 stsz 샘플 크기 합계와 청크 오프셋 목록."""
    total, offsets = 0, []
    for pos, typ, hdr, size, bad in _boxes(data, start, end):
        if bad:
            break
        body = pos + hdr
        if typ in _CONTAINERS:
            t, o = _sample_bytes(data, body, pos + size)
            total += t
            offsets += o
        elif typ == b"stsz":
            fixed, count = struct.unpack(">II", data[body + 4:body + 12])
            if fixed:
                total += fixed * count
            else:
                total += sum(struct.unpack(f">{count}I", data[body + 12:body + 12 + 4 * count]))
        elif typ in (b"stco", b"co64"):
            count = struct.unpack(">I", data[body + 4:body + 8])[0]
            fmt = "I" if typ == b"stco" else "Q"
            sz = 4 if typ == b"stco" else 8
            offsets += list(struct.unpack(f">{count}{fmt}", data[body + 8:body + 8 + sz * count]))
    return total, offsets


def inspect_mp4(data):
    lines, threats, payloads = [], [], []
    if len(data) < 12 or data[4:8] not in (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip"):
        return lines, threats, payloads
    mdats, moov = [], None
    for pos, typ, hdr, size, bad in _boxes(data, 0, len(data)):
        name = typ.decode("latin-1")
        if bad:
            threats.append(("MEDIUM", f"0x{pos:X} 박스 [{name}] 크기 필드 비정상 — 구조 조작 의심"))
            break
        lines.append(f" • MP4 박스 [{name}] @0x{pos:X} ({size:,} B)")
        body = data[pos + hdr:pos + size]
        if typ == b"mdat":
            mdats.append((pos + hdr, size - hdr))
        elif typ == b"moov":
            moov = (pos + hdr, pos + size)
        elif typ in (b"free", b"skip") and body.strip(b"\x00"):
            threats.append(("HIGH" if len(body) > 1024 else "MEDIUM",
                            f"[{name}] 박스(@0x{pos:X})에 0이 아닌 데이터 {len(body):,} B — 패딩 박스 은닉 의심"))
            payloads.append({"category": "MP4 패딩 박스", "fmt": name, "offset": f"0x{pos:X}", "data": body,
                             "detail": "free/skip 박스 내부 데이터", "name": f"mp4_{name}_0x{pos:X}.bin"})
        elif typ == b"uuid" and len(body) > 4096:
            threats.append(("LOW", f"대형 uuid 박스 {len(body):,} B @0x{pos:X} — 벤더 확장일 수 있음, 내용 확인 권장"))
        elif typ not in _TOP_KNOWN:
            threats.append(("MEDIUM", f"비표준 최상위 박스 [{name}] {size:,} B @0x{pos:X}"))
            payloads.append({"category": "MP4 비표준 박스", "fmt": name, "offset": f"0x{pos:X}", "data": body,
                             "detail": "알 수 없는 최상위 박스", "name": f"mp4_box_0x{pos:X}.bin"})
    if moov and mdats:
        used, offsets = _sample_bytes(data, *moov)
        mdat_total = sum(s for _, s in mdats)
        slack = mdat_total - used
        lines.append(f" • mdat {mdat_total:,} B 중 트랙 샘플 {used:,} B 참조 (미참조 {slack:,} B)")
        if slack > max(4096, mdat_total // 100):
            threats.append(("HIGH", f"mdat 안에 어떤 트랙도 참조하지 않는 {slack:,} B — 미디어 데이터 영역 은닉 의심"))
            # 첫 mdat의 마지막 참조 지점 이후를 페이로드로 추출 (흔한 '뒤에 붙이기' 패턴)
            start, size = mdats[-1]
            last_ref = max([o for o in offsets if start <= o < start + size], default=start)
            if last_ref < start + size:
                tail = data[last_ref:start + size]
                payloads.append({"category": "MP4 미참조 mdat", "fmt": "mdat 잔여", "offset": f"0x{last_ref:X}",
                                 "data": tail, "detail": "마지막 청크 오프셋 이후 mdat 영역(마지막 샘플 포함 가능)",
                                 "name": "mdat_unreferenced.bin"})
    return lines, threats, payloads


def inspect(data):
    """포맷을 보고 PNG/MP4 검사를 고른다."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return inspect_png(data)
    if len(data) >= 12 and data[4:8] in (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip"):
        return inspect_mp4(data)
    return [], [], []
