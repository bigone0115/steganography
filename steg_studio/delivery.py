"""
공격 전달(Delivery) 포맷 분석 — RTF / LNK(바로가기) / ISO·IMG 디스크 이미지 / VHD(X). UI 비의존.

메일 첨부로 들어오는 1차 침투 파일은 실행파일 대신 이런 '포장' 포맷을 쓴다.
- RTF  : OLE 객체(\\objdata)에 수식 편집기 익스플로잇(CVE-2017-11882)·Package 파일·OLE2Link(CVE-2017-0199)를 숨김,
         \\objupdate 로 열자마자 객체 갱신, 원격 템플릿(\\*\\template http…), DDEAUTO 필드
- LNK  : 문서 아이콘을 단 바로가기가 실제로는 powershell/mshta 등을 인수와 함께 실행, 인수 공백 패딩으로 속성창 은닉,
         파일 끝에 페이로드 덧붙이기
- ISO/IMG/VHD : 내부 파일에 인터넷 다운로드 표시(MOTW)가 전파되지 않던 점을 악용 — 보이는 LNK + 숨김 DLL/EXE 조합

분석만 하며 아무것도 실행하지 않는다. engine을 import하지 않는다(순환참조 회피, docscan과 같은 규칙).
공개 함수:
    identify(data)  -> (포맷명, 정상 종료 오프셋) 또는 None   — engine.identify_carrier_and_eof에서 사용
    inspect(data)   -> (lines:list[str], threats:list[(grade,msg)], payloads:list[dict])   — container.inspect와 같은 형태
"""

import re
import struct

# 실행·스크립트로 이어지는 확장자 (ISO 내부 파일·Package 객체·바로가기 대상 판정용)
RISKY_EXT = (".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".msc", ".lnk", ".url", ".js", ".jse",
             ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".ps1", ".psm1", ".bat", ".cmd", ".reg", ".jar", ".chm",
             ".iso", ".img", ".vhd", ".vhdx", ".one", ".xll", ".sys")
# 바로가기·RTF 링크가 호출하면 위험한 정상 시스템 도구(LOLBin)
LOLBINS = ("cmd.exe", "powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil",
           "bitsadmin", "msiexec", "forfiles", "conhost", "schtasks", "curl.exe", "wmic", "msbuild", "installutil",
           "regasm", "regsvcs", "cmstp", "odbcconf", "hh.exe", "explorer.exe")
# 명령 인수 속 악성 신호
_ARG_PATTERNS = [
    (r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", "인코딩된 PowerShell 명령(-enc)"),
    (r"-w(indowstyle)?\s+hid", "숨김 창 실행(-WindowStyle Hidden)"),
    (r"https?://|\\\\[\w.\-]+\\", "원격 주소(URL/UNC) 호출"),
    (r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|start-bitstransfer|net\.webclient", "파일 다운로드 명령"),
    (r"\biex\b|invoke-expression", "문자열 코드 실행(IEX)"),
    (r"frombase64string", "Base64 디코딩 후 실행"),
    (r"%temp%|%appdata%|\\appdata\\|\\temp\\", "임시/AppData 폴더 사용"),
]
_DOC_ICON_EXT = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".hwp", ".hwpx", ".txt", ".jpg",
                 ".png", ".rtf", ".zip")

MAX_EXTRACT_ONE = 20 * 1024 * 1024     # 내부 파일 1개 추출 상한
MAX_EXTRACT_TOTAL = 64 * 1024 * 1024   # 디스크 이미지 1개당 총 추출 상한
MAX_ENTRIES = 1000                     # 디렉터리 항목 수 상한(폭탄 방어)
MAX_OBJDATA = 20 * 1024 * 1024         # RTF 객체 1개 디코딩 상한


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _risky(name):
    return name.lower().rstrip(". ").endswith(RISKY_EXT)


# =========================================================================
# 포맷 식별
# =========================================================================
_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


def _is_lnk(d):
    return len(d) >= 76 and _u32(d, 0) == 0x4C and d[4:20] == _LNK_CLSID


def _is_iso(d):
    return len(d) >= 0x8006 and d[0x8001:0x8006] == b"CD001"


def identify(data):
    """전달 포맷이면 (포맷명, 정상 종료 오프셋) — 아니면 None."""
    size = len(data)
    if data.startswith(b"{\\rt"):
        end = data.rfind(b"}")
        return "RTF 문서", (end + 1 if end != -1 else size)
    if _is_lnk(data):
        lnk = _parse_lnk(data)
        return "LNK 바로가기", (lnk["end"] if lnk and lnk["end"] else size)
    if _is_iso(data):
        try:
            vss, bs = _u32(data, 0x8000 + 80), _u16(data, 0x8000 + 128)
            end = vss * bs
            return "ISO/IMG 디스크 이미지", (end if 0 < end <= size else size)
        except struct.error:
            return "ISO/IMG 디스크 이미지", size
    if data.startswith(b"vhdxfile"):
        return "VHDX 가상 디스크", size
    if data.startswith(b"conectix") or (size >= 512 and data[-512:-504] == b"conectix"):
        return "VHD 가상 디스크", size
    return None


# =========================================================================
# RTF
# =========================================================================
def _rtf_group_hex(data, start):
    """start부터 현재 그룹이 닫힐 때까지 16진 문자만 모은다. 사이에 끼운 제어어(\\par 등)·공백 난독화는 무시."""
    out = bytearray()
    depth, i, n = 0, start, len(data)
    while i < n and len(out) < MAX_OBJDATA * 2:
        c = data[i]
        if c == 0x7B:          # {
            depth += 1
        elif c == 0x7D:        # }
            if depth == 0:
                break
            depth -= 1
        elif c == 0x5C:        # \ 제어어: 글자 + 선택적 숫자 인자 건너뜀
            m = re.match(rb"\\([a-zA-Z]+)(-?\d+)? ?", data[i:i + 40])
            if m:
                if m.group(1) == b"bin" and m.group(2):     # \binN = N바이트 원시 데이터
                    i += m.end() + int(m.group(2))
                    continue
                i += m.end()
                continue
            i += 2
            continue
        elif chr(c) in "0123456789abcdefABCDEF":
            out.append(c)
        i += 1
    if len(out) % 2:
        out = out[:-1]
    try:
        return bytes.fromhex(out.decode("ascii"))
    except ValueError:
        return b""


def _cstr(b, o, limit=1024):
    end = b.find(b"\x00", o, o + limit)
    if end == -1:
        return None, o
    return b[o:end].decode("latin-1", "replace"), end + 1


def _parse_ole1(obj):
    """OLE1 객체 헤더 → (class명, 형식 1=링크/2=임베디드, 링크경로, native 데이터)."""
    try:
        fmt = _u32(obj, 4)
        n = _u32(obj, 8)
        cls = obj[12:12 + n].rstrip(b"\x00").decode("latin-1", "replace")
        p = 12 + n
        if fmt == 1:                                  # 링크 객체: topic(=링크 대상) 문자열
            tn = _u32(obj, p)
            topic = obj[p + 4:p + 4 + tn].rstrip(b"\x00").decode("latin-1", "replace")
            return cls, fmt, topic, b""
        p += 4 + _u32(obj, p)                          # topic
        p += 4 + _u32(obj, p)                          # item
        size = _u32(obj, p)
        return cls, fmt, "", obj[p + 4:p + 4 + size]
    except (struct.error, IndexError):
        return "", 0, "", obj


def _parse_package(native):
    """OLE1 'Package' 네이티브 데이터 → (표시이름, 원본경로, 파일 데이터) — 실패 시 None."""
    try:
        label, p = _cstr(native, 2)
        src, p = _cstr(native, p)
        p += 4                                          # 0x00030000
        tlen = _u32(native, p)
        p += 4 + tlen                                   # 임시 경로
        dlen = _u32(native, p)
        data = native[p + 4:p + 4 + dlen]
        if label is None or len(data) != dlen:
            return None
        return label, src or "", data
    except (struct.error, IndexError):
        return None


def _inspect_rtf(data, lines, threats, payloads):
    lines.append("[RTF 문서 구조]")
    classes = [m.decode("latin-1") for m in re.findall(rb"\\objclass\s+([^}\\]+)", data)]
    objs = [m.end() for m in re.finditer(rb"\\objdata\b", data)]
    lines.append(f"   - OLE 객체(\\objdata) {len(objs)}개" + (f", 선언된 클래스: {', '.join(classes[:10])}" if classes else ""))
    if re.search(rb"\\objupdate\b", data):
        threats.append(("HIGH", "RTF \\objupdate — 문서를 여는 즉시 OLE 객체를 자동 갱신(클릭 없이 실행 유도)"))
    if re.search(rb"\\objautlink\b|\\objlink\b", data):
        threats.append(("HIGH", "RTF 링크 객체(\\objautlink/\\objlink) — 외부 대상 자동 연결"))
    tpl = re.search(rb"\\\*\\template\s+([^}]+)", data)
    if tpl and re.search(rb"https?://|\\\\\\\\", tpl.group(1)):
        threats.append(("HIGH", f"RTF 원격 템플릿 주입: {tpl.group(1)[:120].decode('latin-1', 'replace').strip()}"))
    for m in re.finditer(rb"\\fldinst[^}]{0,40}?\b(DDEAUTO|DDE)\b([^}]{0,200})", data, re.I):
        threats.append(("HIGH", f"RTF DDE 필드({m.group(1).decode()}) — 외부 명령 실행: {m.group(2)[:100].decode('latin-1', 'replace').strip()}"))

    for k, start in enumerate(objs[:20], 1):
        obj = _rtf_group_hex(data, start)
        if not obj:
            continue
        cls, fmt, topic, native = _parse_ole1(obj)
        kind = {1: "링크", 2: "임베디드"}.get(fmt, "알 수 없음")
        lines.append(f"   - 객체 #{k}: 클래스 '{cls or '?'}' ({kind}), 디코딩 {len(obj):,} B")
        low = cls.lower()
        if low.startswith(("equation", "microsoft equation")):
            threats.append(("CRITICAL", f"RTF 수식 편집기 OLE 객체('{cls}') — CVE-2017-11882/CVE-2018-0802 익스플로잇 단골 경로"))
        elif low in ("ole2link", "htmlfile") or "ole2link" in low:
            threats.append(("CRITICAL", f"RTF '{cls}' 객체 — 원격 HTA/스크립트 로드(CVE-2017-0199 계열)"))
        if fmt == 1 and topic:
            threats.append(("HIGH", f"RTF 링크 객체 대상: {topic[:150]}"))
        name, body, detail = f"rtf_object_{k}.bin", native or obj, f"RTF OLE 객체 #{k} ({cls or '?'})"
        if low == "package":
            pkg = _parse_package(native)
            if pkg:
                label, src, body = pkg
                name = label or name
                detail = f"RTF Package 포장 파일 '{label}' (원본 경로: {src[:120]})"
                threats.append(("HIGH" if _risky(label) else "MEDIUM",
                                f"RTF에 파일 포장(Package) 객체 '{label}'" + (" — 실행형 확장자" if _risky(label) else "")))
        if body:
            payloads.append({"category": "RTF 객체", "fmt": f"OLE 객체: {cls or '?'}", "offset": f"objdata #{k}",
                             "data": body, "detail": detail, "name": name})
    if not objs and not threats:
        lines.append("   - 객체·외부 연결 없음")


# =========================================================================
# LNK (Shell Link, MS-SHLLINK)
# =========================================================================
def _parse_lnk(d):
    """바로가기 구조 해석 → dict(target, args, icon, workdir, name, show, net, env, end). 손상 시 None."""
    try:
        flags = _u32(d, 0x14)
        info = {"show": _u32(d, 0x3C), "target": "", "args": "", "icon": "", "workdir": "", "name": "",
                "relpath": "", "net": "", "env": "", "end": 0}
        p = 76
        if flags & 0x1:                                       # HasLinkTargetIDList
            p += 2 + _u16(d, p)
        if flags & 0x2:                                       # HasLinkInfo
            li = p
            li_size, li_flags = _u32(d, li), _u32(d, li + 8)
            if li_flags & 0x1:                                # VolumeIDAndLocalBasePath
                info["target"], _ = _cstr(d, li + _u32(d, li + 16), 1024)
            if li_flags & 0x2:                                # CommonNetworkRelativeLinkAndPathSuffix
                cn = li + _u32(d, li + 20)
                info["net"], _ = _cstr(d, cn + _u32(d, cn + 8), 1024)
            p += li_size
        unicode = bool(flags & 0x80)
        for bit, key in ((0x4, "name"), (0x8, "relpath"), (0x10, "workdir"), (0x20, "args"), (0x40, "icon")):
            if flags & bit:
                n = _u16(d, p)
                raw = d[p + 2:p + 2 + n * (2 if unicode else 1)]
                info[key] = raw.decode("utf-16-le" if unicode else "latin-1", "replace")
                p += 2 + len(raw)
        while p + 4 <= len(d):                                # ExtraData 블록 (크기 < 4 = 종료 블록)
            bsz = _u32(d, p)
            if bsz < 4:
                p += 4
                break
            if bsz >= 8 and _u32(d, p + 4) == 0xA0000001 and p + 788 <= len(d):   # EnvironmentVariableDataBlock
                info["env"] = d[p + 268:p + 788].decode("utf-16-le", "replace").split("\x00")[0] or \
                    _cstr(d, p + 8, 260)[0] or ""
            p += bsz
        info["end"] = min(p, len(d))
        return info
    except (struct.error, IndexError, TypeError):
        return None


def _inspect_lnk(data, lines, threats, payloads):
    info = _parse_lnk(data)
    lines.append("[LNK 바로가기 구조]")
    if not info:
        threats.append(("MEDIUM", "LNK 구조 손상 — 파서 회피용 변조 의심"))
        return
    target = info["target"] or info["env"] or info["relpath"] or info["net"]
    cmd = f"{target} {info['args']}".strip()
    for k, label in (("target", "대상"), ("env", "대상(환경변수)"), ("relpath", "상대경로"), ("net", "네트워크 경로"),
                     ("workdir", "작업 폴더"), ("args", "인수"), ("icon", "아이콘"), ("name", "설명")):
        if info[k]:
            v = info[k]
            lines.append(f"   - {label}: {v[:200]}" + (f" … (총 {len(v):,}자)" if len(v) > 200 else ""))
    low = cmd.lower()
    lol = [b for b in LOLBINS if b in low]
    if lol:
        threats.append(("HIGH", f"바로가기가 시스템 도구를 실행: {', '.join(lol)} — LOLBin 악용 의심"))
    for pat, why in _ARG_PATTERNS:
        if re.search(pat, info["args"] + " " + target, re.I):
            threats.append(("HIGH", f"바로가기 인수: {why}"))
    if info["net"] or target.startswith("\\\\"):
        threats.append(("HIGH", f"바로가기 대상이 네트워크 공유/WebDAV: {(info['net'] or target)[:120]}"))
    if len(info["args"]) > 260 or re.match(r"\s{20,}", info["args"]):
        threats.append(("MEDIUM", f"인수 길이 {len(info['args']):,}자/선행 공백 패딩 — 속성 창에서 명령을 숨기는 기법"))
    if info["show"] == 7:
        threats.append(("MEDIUM", "창 최소화·비활성 실행(SW_SHOWMINNOACTIVE) — 사용자 몰래 실행"))
    icon = info["icon"].lower()
    if (lol or _risky(target)) and (icon.endswith(_DOC_ICON_EXT) or re.search(r"shell32|imageres|moricons", icon)):
        threats.append(("MEDIUM", f"아이콘 위장: 실행 대상과 다른 문서/시스템 아이콘 사용 ({info['icon'][:80]})"))
    if info["end"] and info["end"] < len(data):
        lines.append(f"   - 구조 종료 0x{info['end']:X} 뒤 덧붙은 데이터 {len(data) - info['end']:,} B")
    if cmd:
        payloads.append({"category": "LNK 실행 명령", "fmt": "바로가기 명령줄", "offset": "StringData",
                         "data": cmd.encode("utf-8"), "detail": f"바로가기가 실행하는 명령 ({len(cmd):,}자)",
                         "name": "lnk_command.txt", "decoded": cmd})


# =========================================================================
# ISO 9660 / IMG / VHD
# =========================================================================
def _iso_volume(d):
    """(블록크기, 루트 레코드 오프셋, Joliet 여부) — Joliet(유니코드 이름)이 있으면 우선."""
    best = None
    for sec in range(16, 64):
        o = sec * 2048
        if o + 2048 > len(d) or d[o + 1:o + 6] != b"CD001":
            break
        vtype = d[o]
        if vtype == 255:
            break
        if vtype == 1 and best is None:
            best = (_u16(d, o + 128), o + 156, False)
        if vtype == 2 and d[o + 88:o + 91] in (b"%/@", b"%/C", b"%/E"):
            best = (_u16(d, o + 128), o + 156, True)
    return best


def _iso_files(d):
    """ISO 파일 목록 [(경로, 오프셋, 크기, 숨김)] — 깊이 8·항목 1000 상한."""
    vol = _iso_volume(d)
    if not vol:
        return []
    bs, root, joliet = vol
    out, seen = [], set()

    def walk(extent, size, path, depth):
        if depth > 8 or extent in seen or len(out) >= MAX_ENTRIES:
            return
        seen.add(extent)
        o, end = extent * bs, min(extent * bs + size, len(d))
        while o < end and len(out) < MAX_ENTRIES:
            rl = d[o]
            if rl == 0:                                   # 섹터 끝 패딩 → 다음 섹터
                o = (o // bs + 1) * bs
                continue
            ext_, dlen, fl, nl = _u32(d, o + 2), _u32(d, o + 10), d[o + 25], d[o + 32]
            raw = d[o + 33:o + 33 + nl]
            if raw not in (b"\x00", b"\x01"):
                name = raw.decode("utf-16-be", "replace") if joliet else raw.decode("latin-1", "replace")
                name = name.split(";")[0]
                if fl & 0x2:
                    walk(ext_, dlen, f"{path}{name}/", depth + 1)
                else:
                    out.append((path + name, ext_ * bs, dlen, bool(fl & 0x1)))
            o += rl

    walk(_u32(d, root + 2), _u32(d, root + 10), "/", 0)
    return out


def _inspect_iso(data, lines, threats, payloads):
    files = _iso_files(data)
    lines.append(f"[ISO/IMG 디스크 이미지 — 파일 {len(files)}개]")
    if not files:
        lines.append("   - 파일시스템 목록을 읽지 못함 (UDF 전용 등) — 시그니처 카빙 결과 참고")
        return
    total = 0
    risky, hidden = [], []
    for path, off, size, hid in files:
        flag = (" [숨김]" if hid else "") + (" [실행형]" if _risky(path) else "")
        lines.append(f"   - {path} ({size:,} B){flag}")
        if _risky(path):
            risky.append(path)
        if hid:
            hidden.append(path)
        if size and size <= MAX_EXTRACT_ONE and total + size <= MAX_EXTRACT_TOTAL and off + size <= len(data):
            total += size
            payloads.append({"category": "디스크 이미지 내부 파일", "fmt": "ISO 파일", "offset": f"0x{off:X}",
                             "data": data[off:off + size], "detail": f"ISO 내부 {path}" + flag,
                             "name": path.rsplit("/", 1)[-1] or "iso_file.bin"})
    if risky:
        threats.append(("HIGH", f"디스크 이미지 안에 실행형 파일 {len(risky)}개: {', '.join(p.rsplit('/', 1)[-1] for p in risky[:6])}"
                                " — 메일 첨부 ISO/IMG로 인터넷 다운로드 표시(MOTW)를 우회하는 전달 기법"))
    lnks = [p for p in files if p[0].lower().endswith(".lnk") and not p[3]]
    if lnks and hidden:
        threats.append(("CRITICAL", f"보이는 바로가기 {len(lnks)}개 + 숨김 파일 {len(hidden)}개 조합 — "
                                    "사용자가 LNK를 열면 숨긴 DLL/스크립트가 실행되는 전형적 악성 ISO 구성"))
    elif hidden:
        threats.append(("MEDIUM", f"숨김 속성 파일 {len(hidden)}개: {', '.join(p.rsplit('/', 1)[-1] for p in hidden[:6])}"))
    if len(files) > len(payloads):
        lines.append(f"   - 크기 상한으로 {len(files) - len(payloads)}개 파일은 추출하지 않음")


# =========================================================================
# 진입점
# =========================================================================
def inspect(data):
    """전달 포맷이면 구조 해석 결과, 아니면 빈 결과."""
    lines, threats, payloads = [], [], []
    try:
        if data.startswith(b"{\\rt"):
            _inspect_rtf(data, lines, threats, payloads)
        elif _is_lnk(data):
            _inspect_lnk(data, lines, threats, payloads)
        elif _is_iso(data):
            _inspect_iso(data, lines, threats, payloads)
        elif data.startswith(b"vhdxfile") or data.startswith(b"conectix") or data[-512:-504] == b"conectix":
            lines.append("[VHD/VHDX 가상 디스크]")
            threats.append(("MEDIUM", "가상 디스크 이미지 — 더블클릭 시 자동 마운트, 내부 파일에 MOTW 미전파(전달 기법). "
                                      "내부 파일시스템은 시그니처 카빙 결과만 참고"))
    except Exception as e:                                # 손상 파일이 스캔 전체를 깨지 않게
        lines.append(f"   - 구조 해석 예외: {e}")
    return lines, threats, payloads
