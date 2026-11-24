"""
포렌식 스캔 엔진 (UI 완전 비의존).

tkinter/Qt 어떤 GUI에서도 재사용할 수 있도록, 스캔 로직을 위젯 호출 없이
구조화된 결과(ScanResult)로 반환한다. 순수 헬퍼는 crypto/analysis 모듈을 재사용한다.

핵심 진입점:
    scan_file(path, password="", log=None) -> ScanResult
    build_embed(...) 계열은 embed.py 참고 (은닉 생성)
"""

import io
import os
import re
import bz2
import gzip
import json
import wave
import base64
import struct
import hashlib
import binascii
import urllib.request
import urllib.error
from dataclasses import dataclass, field

from . import crypto, analysis, docscan, steganalysis, ioc, container, ml, video
from .constants import LSB_MAGIC, EOF_MAGIC, MAX_SCAN_FILE_BYTES

# 사용자 지정 YARA 룰 폴더(.yar). GUI가 set_user_yara_dir()로 설정. UI 비의존 유지용 모듈 전역.
USER_YARA_DIR = None
_user_yara_cache = {}   # dir -> (mtime_sig, compiled_rules)


def set_user_yara_dir(path):
    """사용자 YARA 룰 폴더를 지정(엔진 전역). None/빈값이면 사용자 룰 비활성."""
    global USER_YARA_DIR
    USER_YARA_DIR = path or None

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import yara
    YARA_ENGINE_AVAILABLE = True
except ImportError:
    YARA_ENGINE_AVAILABLE = False


@dataclass
class CarvedItem:
    category: str
    format: str
    offset: str
    data: bytes
    detail: str
    name: str
    decoded_text: str = None
    id: int = 0

    @property
    def size(self):
        return len(self.data) if self.data else 0


@dataclass
class ScanResult:
    filename: str = ""
    filepath: str = ""
    filesize: int = 0
    sha256: str = ""
    md5: str = ""
    sha1: str = ""
    carrier_fmt: str = ""
    natural_eof: int = 0
    overall_entropy: float = 0.0
    findings: list = field(default_factory=list)
    carved: list = field(default_factory=list)      # list[CarvedItem]
    meta_report: str = ""
    log_lines: list = field(default_factory=list)
    file_bytes: bytes = b""
    iocs: dict = field(default_factory=dict)        # 종류 -> [값]


# =========================================================================
# 언어/코드 패턴 시그니처 (모듈 상수로 1회만 정의)
# =========================================================================
LANG_PATTERNS = {
    "Python": rb"\b(def\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(|import\s+[a-zA-Z0-9_]+|from\s+[a-zA-Z0-9_\.]+\s+import|if\s+__name__\s*==)",
    "JavaScript / TypeScript": rb"\b(function\s+[a-zA-Z0-9_]*\s*\(|const\s+[a-zA-Z0-9_]+\s*=|let\s+[a-zA-Z0-9_]+\s*=|console\.log\s*\(|document\.getElementById|export\s+default\b)",
    "C / C++": rb"(#include\s*[<\"][a-zA-Z0-9_\.\/]+[>\"]|\bint\s+main\s*\(|std::cout|printf\s*\(|malloc\s*\()",
    "Java": rb"\b(public\s+class\s+[A-Z][a-zA-Z0-9_]*|public\s+static\s+void\s+main|System\.out\.println|import\s+java\.)",
    "C# (.NET)": rb"\b(using\s+System;|namespace\s+[a-zA-Z0-9_\.]+|Console\.WriteLine\s*\()",
    "Go (Golang)": rb"\b(package\s+main\b|func\s+main\s*\(\s*\)|fmt\.Println\s*\()",
    "Rust": rb"\b(fn\s+main\s*\(\s*\)|let\s+mut\s+[a-zA-Z_]|println!\s*\(|use\s+std::)",
    "Kotlin": rb"\b(fun\s+main\s*\(|val\s+[a-zA-Z0-9_]+\s*=|var\s+[a-zA-Z0-9_]+\s*:)",
    "Swift": rb"\b(import\s+(Foundation|UIKit|SwiftUI)|func\s+[a-zA-Z0-9_]+\s*\(|guard\s+let\b)",
    "Dart": rb"\b(import\s+['\"]package:|void\s+main\s*\(\s*\)\s*\{|Widget\s+build\s*\()",
    "PHP": rb"(<\?php\b|\$_GET\[|\$_POST\[|\$_SERVER\[)",  # echo 는 셸과 겹쳐 제외
    "Ruby": rb"\b(require\s+['\"][a-zA-Z0-9_\/]+['\"]|def\s+[a-zA-Z0-9_]+.*\bend\b|puts\s+['\"])",
    "Perl": rb"\b(use\s+strict;|use\s+warnings;|my\s+\$[a-zA-Z_])",
    "Lua": rb"\b(local\s+function\s+[a-zA-Z_]|elseif\b.*\bthen\b)",
    "R": rb"([a-zA-Z0-9_\.]+\s*<-\s*function\s*\(|library\s*\([a-zA-Z0-9_]+\))",
    "Julia": rb"\b(function\s+[a-zA-Z0-9_!]+\(.*\)\s*\n|using\s+LinearAlgebra)",
    "Scala": rb"\b(object\s+[A-Z][a-zA-Z0-9_]*\s+extends\s+App|def\s+main\s*\(\s*args:\s*Array\[String\]\))",
    "Haskell": rb"\b(module\s+[A-Z][a-zA-Z0-9_\.]*\s+where|import\s+qualified\s+|putStrLn\s+)",
    "Elixir / Erlang": rb"\b(defmodule\s+[A-Z][a-zA-Z0-9_\.]*\s+do|defp?\s+[a-z_]+\s*\(|-module\([a-z0-9_]+\)\.)",
    "Solidity": rb"\b(pragma\s+solidity\s+[\^>=0-9\.]+|contract\s+[A-Z][a-zA-Z0-9_]*\s*\{)",
    "Zig": rb"\b(const\s+std\s*=\s*@import\(\"std\"\)|pub\s+fn\s+main\s*\()",
    "COBOL": rb"\b(IDENTIFICATION\s+DIVISION\.|PROGRAM-ID\.|PROCEDURE\s+DIVISION\.)",
    "Shell (Bash/Zsh)": rb"(#!\s*/bin/(bash|sh|zsh|env)|echo\s+\$[a-zA-Z_]|if\s+\[\[\s+)",
    "PowerShell": rb"\b(Invoke-Expression|Write-Host\s+|\$PSVersionTable|Get-Process\b|-EncodedCommand\b)",
    "Windows Batch": rb"(@echo\s+off\b|setlocal\s+enabledelayedexpansion|goto\s+:[a-zA-Z0-9_]+)",
    "SQL": rb"\b(SELECT\s+.+\s+FROM\s+[a-zA-Z0-9_]+|INSERT\s+INTO\s+[a-zA-Z0-9_]+\s+VALUES|CREATE\s+TABLE\s+)",
    "HTML / Script": rb"(<!DOCTYPE\s+html>|<\s*script\b[^>]*>|<\s*iframe\b)",
    "CSS": rb"(@media\s+screen\s+and|\.[a-zA-Z0-9_-]+\s*\{\s*(display|color|margin|padding)\s*:)",
    "XML / SVG": rb"(<\?xml\s+version=['\"]1\.0|<svg\s+xmlns=)",
    "Assembly (x86/ARM)": rb"\b(section\s+\.(text|data)|global\s+_start\b|mov\s+(eax|rax|ebx|rdi),\s*)",
    "WebAssembly (Wasm)": rb"\x00asm\x01\x00\x00\x00",
    "Java Class Bytecode": rb"\xca\xfe\xba\xbe\x00\x00",
    "Windows PE (EXE/DLL)": rb"MZ\x90\x00\x03\x00\x00\x00",
    "Linux ELF Binary": rb"\x7fELF\x02\x01\x01\x00",
    "macOS Mach-O Binary": rb"(\xfe\xed\xfa\xce|\xce\xfa\xed\xfe|\xcf\xfa\xed\xfe)",
}


def scan_all_languages_and_deobfuscate(data: bytes):
    """코드 시그니처 + URL/Base64/Hex 디코딩 + 1바이트 XOR 브루트포스 휴리스틱."""
    matched_langs = []
    decoded_preview = None
    sample = data[:32768]

    if sample.startswith(b"\x1f\x8b\x08"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                decomp = gz.read(1024 * 1024)
            decoded_preview = f"[Gzip 압축 자동 해제 (상위 {len(decomp):,} B)]\n" + decomp[:4000].decode("utf-8", errors="replace")
            sample = decomp[:32768]
            matched_langs.append("Gzip 중첩 압축 페이로드")
        except Exception:
            pass
    elif sample.startswith(b"BZh"):
        try:
            bzd = bz2.BZ2Decompressor()
            decomp = bzd.decompress(data[:1024 * 1024], max_length=1024 * 1024)
            decoded_preview = f"[Bzip2 압축 자동 해제 (상위 {len(decomp):,} B)]\n" + decomp[:4000].decode("utf-8", errors="replace")
            sample = decomp[:32768]
            matched_langs.append("Bzip2 중첩 압축 페이로드")
        except Exception:
            pass

    for lang_name, pattern in LANG_PATTERNS.items():
        if re.search(pattern, sample):
            matched_langs.append(lang_name)

    if sample.count(b"%") >= 12 and re.search(rb"(%[0-9a-fA-F]{2}){6,}", sample):
        try:
            unquoted = urllib.parse.unquote_to_bytes(sample)
            for lang_name, pattern in LANG_PATTERNS.items():
                if re.search(pattern, unquoted):
                    tag = f"{lang_name} (URL 디코딩)"
                    if tag not in matched_langs:
                        matched_langs.append(tag)
                    decoded_preview = unquoted[:4000].decode("utf-8", errors="replace")
        except Exception:
            pass

    for b64_cand in re.findall(rb"[A-Za-z0-9+/]{64,}={0,2}", sample)[:5]:
        try:
            raw_dec = base64.b64decode(b64_cand)
            for lang_name, pattern in LANG_PATTERNS.items():
                if re.search(pattern, raw_dec):
                    tag = f"{lang_name} (Base64 디코딩)"
                    if tag not in matched_langs:
                        matched_langs.append(tag)
                    decoded_preview = raw_dec[:4000].decode("utf-8", errors="replace")
        except Exception:
            pass

    for hex_cand in re.findall(rb"\b[0-9a-fA-F]{64,}\b", sample)[:5]:
        if len(hex_cand) % 2 == 0:
            try:
                raw_dec = binascii.unhexlify(hex_cand)
                for lang_name, pattern in LANG_PATTERNS.items():
                    if re.search(pattern, raw_dec):
                        tag = f"{lang_name} (Hex 디코딩)"
                        if tag not in matched_langs:
                            matched_langs.append(tag)
                        decoded_preview = raw_dec[:4000].decode("utf-8", errors="replace")
            except Exception:
                pass

    if not matched_langs and 16 <= len(sample) <= 65536:
        xor_window = sample[:2048]
        xor_probes = [
            (b"#!/bin/", "Shell 스크립트"), (b"import ", "Python/JS 모듈"),
            (b"def ", "Python 함수"), (b"function ", "JavaScript 함수"),
            (b"<?php", "PHP 스크립트"), (b"Invoke-Expression", "PowerShell 명령"),
            (b"#include <", "C/C++ 소스코드"), (b"MZ\x90\x00\x03", "Windows PE 실행파일"),
        ]
        for xor_key in range(1, 256):
            xored = bytes(b ^ xor_key for b in xor_window)
            hit_label = next((pname for pbytes, pname in xor_probes if pbytes in xored), None)
            if hit_label:
                matched_langs.append(f"{hit_label} (XOR Key 0x{xor_key:02X} 복원)")
                full_xored = bytes(b ^ xor_key for b in sample[:4096])
                decoded_preview = f"[1-Byte XOR 브루트포스 복원! Key: 0x{xor_key:02X}]\n" + full_xored.decode("utf-8", errors="replace")
                break

    heur_sample = sample[:16384]
    if not heur_sample:
        return matched_langs, {"is_code": False, "printable": 0.0, "density": 0.0}, decoded_preview

    printable_chars = sum(1 for b in heur_sample if 32 <= b <= 126 or b in (9, 10, 13))
    printable_ratio = printable_chars / len(heur_sample)
    syntax_tokens = set(b"{}()[];=<>:+-*/&|!~%^")
    token_count = sum(1 for b in heur_sample if b in syntax_tokens)
    token_density = token_count / len(heur_sample)
    newline_count = heur_sample.count(b"\n")
    is_heuristic_code = (printable_ratio >= 0.85 and token_density >= 0.045 and newline_count >= 2)
    return matched_langs, {"is_code": is_heuristic_code, "printable": printable_ratio, "density": token_density}, decoded_preview


def run_yara_or_regex_rules(raw_data: bytes, decoded_text: str = None):
    """악성 명령 패턴(리버스셸/동적실행/웹셸/PE·ELF)을 YARA 엔진 또는 내장 정규식으로 매칭. 매칭된 룰 이름 리스트 반환."""
    combined = raw_data[:65536]
    if decoded_text:
        combined += b"\n" + decoded_text.encode("utf-8", errors="ignore")

    if YARA_ENGINE_AVAILABLE:
        yara_src = """
        rule Reverse_Shell_Indicator {
            strings:
                $s1 = "/bin/sh -i" nocase
                $s2 = "/bin/bash -i" nocase
                $s3 = "nc -e /bin/" nocase
            condition: any of them
        }
        rule Suspicious_Dynamic_Exec {
            strings:
                $e1 = "eval(base64_decode" nocase
                $e2 = "Invoke-Expression" nocase
                $e3 = "-WindowStyle Hidden" nocase
                $e4 = "WScript.Shell" nocase
            condition: any of them
        }
        """
        try:
            rules = yara.compile(source=yara_src)
            matches = rules.match(data=combined)
            if matches:
                return [f"YARA엔진:{m.rule}" for m in matches]
        except Exception:
            pass

    regex_rules = {
        "RegexPattern:Reverse_Shell": rb"(/bin/(ba)?sh\s+-i|nc\s+-e\s+/bin/|bash\s+-c\s+['\"]bash\s+-i)",
        "RegexPattern:Dynamic_Eval_Exec": rb"(eval\s*\(\s*base64_decode|exec\s*\(\s*compile|WScript\.Shell)",
        "RegexPattern:PowerShell_Hidden": rb"(-WindowStyle\s+Hidden|DownloadString\s*\(|FromBase64String)",
        "RegexPattern:WebShell_Backdoor": rb"(passthru\s*\(|shell_exec\s*\(|assert\s*\(\s*\$_(POST|GET|REQUEST))",
        "RegexPattern:Embedded_PE_ELF": rb"(MZ\x90\x00\x03\x00\x00\x00|\x7fELF\x02\x01\x01)",
    }
    hits = [name for name, pat in regex_rules.items() if re.search(pat, combined, re.IGNORECASE)]
    hits += _match_user_yara(combined)
    return hits


def _match_user_yara(combined):
    """사용자 지정 폴더의 .yar 룰을 컴파일·캐시하여 매칭. 매칭된 룰 이름 리스트 반환."""
    if not (YARA_ENGINE_AVAILABLE and USER_YARA_DIR and os.path.isdir(USER_YARA_DIR)):
        return []
    try:
        files = {}
        sig = []
        for fn in sorted(os.listdir(USER_YARA_DIR)):
            if fn.lower().endswith((".yar", ".yara")):
                fp = os.path.join(USER_YARA_DIR, fn)
                files[fn] = fp
                sig.append((fn, os.path.getmtime(fp)))
        if not files:
            return []
        sig = tuple(sig)
        cached = _user_yara_cache.get(USER_YARA_DIR)
        if not cached or cached[0] != sig:
            rules = yara.compile(filepaths=files)
            _user_yara_cache[USER_YARA_DIR] = (sig, rules)
        else:
            rules = cached[1]
        return [f"YARA사용자룰:{m.rule}" for m in rules.match(data=combined)]
    except Exception:
        return []


# =========================================================================
# 컨테이너 종료지점(Natural EOF) 파서
# =========================================================================
def _read_ebml_vint(data, pos, mask_length_bit=True):
    """MKV/WebM(EBML)의 가변 길이 정수(VINT)를 pos에서 읽어 (값, 바이트길이) 반환."""
    if pos >= len(data):
        return None, 0
    first = data[pos]
    if first == 0:
        return None, 0
    length = 1
    mask = 0x80
    while length <= 8 and not (first & mask):
        length += 1
        mask >>= 1
    if length > 8 or pos + length > len(data):
        return None, 0
    val = (first & (mask - 1)) if mask_length_bit else first
    for i in range(1, length):
        val = (val << 8) | data[pos + i]
    return val, length


def _parse_ebml_natural_eof(data):
    """MKV/WebM의 최상위 EBML 요소를 순회해 실제 컨테이너 종료 오프셋을 계산."""
    size = len(data)
    pos = 0
    while pos < size:
        elem_id, id_len = _read_ebml_vint(data, pos, mask_length_bit=False)
        if elem_id not in (0x1A45DFA3, 0x18538067) or id_len == 0:
            break
        pos += id_len
        elem_size, sz_len = _read_ebml_vint(data, pos, mask_length_bit=True)
        if elem_size is None or sz_len == 0:
            break
        pos += sz_len
        if elem_size == (1 << (7 * sz_len)) - 1 or pos + elem_size > size:
            return size
        pos += elem_size
    return pos if pos > 0 else size


def _parse_mp3_natural_eof(data):
    """ID3 태그 + MPEG 오디오 프레임 체인을 추적해 MP3의 실제 종료 오프셋을 계산."""
    size = len(data)
    pos = 0
    if data.startswith(b"ID3") and size >= 10:
        s0, s1, s2, s3 = data[6], data[7], data[8], data[9]
        id3_size = ((s0 & 0x7F) << 21) | ((s1 & 0x7F) << 14) | ((s2 & 0x7F) << 7) | (s3 & 0x7F)
        pos = 10 + id3_size

    bitrates_v1_l3 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
    bitrates_v2_l3 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0]
    samplerates_v1 = [44100, 48000, 32000, 0]
    samplerates_v2 = [22050, 24000, 16000, 0]
    samplerates_v25 = [11025, 12000, 8000, 0]

    valid_frames = 0
    while pos + 4 <= size:
        if data[pos:pos + 3] == b"TAG" and pos + 128 <= size:
            pos += 128
            break
        if data[pos] != 0xFF or (data[pos + 1] & 0xE0) != 0xE0:
            break
        b1, b2 = data[pos + 1], data[pos + 2]
        ver_bits = (b1 >> 3) & 0x03
        layer_bits = (b1 >> 1) & 0x03
        br_idx = (b2 >> 4) & 0x0F
        sr_idx = (b2 >> 2) & 0x03
        padding = (b2 >> 1) & 0x01
        if ver_bits == 1 or layer_bits != 1 or br_idx in (0, 15) or sr_idx == 3:
            break
        if ver_bits == 3:
            br = bitrates_v1_l3[br_idx] * 1000
            sr = samplerates_v1[sr_idx]
            frame_len = int((144 * br) // sr + padding)
        else:
            br = bitrates_v2_l3[br_idx] * 1000
            sr = samplerates_v2[sr_idx] if ver_bits == 2 else samplerates_v25[sr_idx]
            frame_len = int((72 * br) // sr + padding)
        if frame_len < 24 or pos + frame_len > size:
            break
        pos += frame_len
        valid_frames += 1
    return pos if valid_frames > 0 else size


def _parse_zip_natural_eof(data):
    """ZIP/OOXML의 End of Central Directory(PK\x05\x06)를 찾아 정상 종료 오프셋 반환(없으면 전체 길이)."""
    eocd = data.rfind(b"PK\x05\x06")
    if eocd != -1 and eocd + 22 <= len(data):
        comment_len = struct.unpack("<H", data[eocd + 20:eocd + 22])[0]
        if eocd + 22 + comment_len <= len(data):
            return eocd + 22 + comment_len
    return len(data)


def identify_carrier_and_eof(data):
    """파일 선두 매직으로 컨테이너 포맷을 식별하고, 그 포맷의 '정상 종료 지점(natural EOF)' 오프셋을 계산해 (포맷명, EOF) 반환."""
    size = len(data)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        pos = 8
        while pos + 12 <= size:
            chunk_len = struct.unpack(">I", data[pos:pos + 4])[0]
            chunk_type = data[pos + 4:pos + 8]
            if pos + 12 + chunk_len > size:
                break
            pos += 12 + chunk_len
            if chunk_type == b"IEND":
                return "PNG 이미지", min(pos, size)
        return "PNG 이미지", size
    if data.startswith(b"\xff\xd8\xff"):
        pos = 2
        while pos + 2 <= size:
            if data[pos] != 0xFF:
                pos += 1
                continue
            marker = data[pos + 1]
            if marker == 0xD9:
                return "JPEG 이미지", pos + 2
            elif marker == 0xDA:
                pos += 2
                while pos + 2 <= size:
                    if data[pos] == 0xFF and data[pos + 1] == 0xD9:
                        return "JPEG 이미지", pos + 2
                    pos += 1
                break
            elif marker in (0xD8, 0x01) or (0xD0 <= marker <= 0xD7):
                pos += 2
            else:
                if pos + 4 <= size:
                    seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                    if seg_len < 2:
                        break
                    pos += 2 + seg_len
                else:
                    break
        return "JPEG 이미지", size
    if data.startswith((b"GIF87a", b"GIF89a")):
        trailer = data.rfind(b"\x00\x3b")
        return "GIF 이미지", (trailer + 2 if trailer != -1 else size)
    if data.startswith(b"RIFF") and size >= 12:
        riff_size = struct.unpack("<I", data[4:8])[0] + 8
        sub_fmt = data[8:12]
        lbl = {"WEBP": "WEBP 이미지", "AVI ": "AVI 동영상", "WAVE": "WAV 오디오"}.get(sub_fmt.decode("latin1", errors="ignore"), "RIFF 미디어")
        return lbl, min(riff_size, size)
    if data.startswith(b"BM") and size >= 14:
        bmp_size = struct.unpack("<I", data[2:6])[0]
        return "BMP 이미지", (bmp_size if 14 <= bmp_size <= size else size)
    if size >= 12 and data[4:8] in (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip"):
        pos = 0
        valid_boxes = 0
        known_boxes = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta", b"pdin", b"styp", b"sidx", b"moof", b"mfra"}
        while pos + 8 <= size:
            box_size = struct.unpack(">I", data[pos:pos + 4])[0]
            box_type = data[pos + 4:pos + 8]
            if box_type not in known_boxes and not all(32 <= b <= 126 for b in box_type):
                break
            if box_size == 1 and pos + 16 <= size:
                box_size = struct.unpack(">Q", data[pos + 8:pos + 16])[0]
            elif box_size == 0:
                pos = size
                valid_boxes += 1
                break
            if box_size < 8 or pos + box_size > size:
                break
            pos += box_size
            valid_boxes += 1
        if valid_boxes > 0:
            return "MP4/MOV 동영상", pos
    if data.startswith(b"\x1a\x45\xdf\xa3"):
        return "MKV/WebM 동영상", _parse_ebml_natural_eof(data)
    if data.startswith(b"ID3") or (size >= 4 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0):
        return "MP3 오디오", _parse_mp3_natural_eof(data)
    if data.startswith(b"%PDF"):
        eof_idx = data.rfind(b"%%EOF")
        if eof_idx != -1:
            end_pos = eof_idx + 5
            while end_pos < size and data[end_pos:end_pos + 1] in (b"\r", b"\n", b" "):
                end_pos += 1
            return "PDF 문서", end_pos
        return "PDF 문서", size
    # 문서형(HWP/Office/OOXML) 식별 — 구조 분석은 docscan이 담당
    doc_type = docscan.detect_document_type(data)
    # ZIP 계열(OOXML/HWPX/일반 ZIP)은 EOCD로 실제 종료점 계산 → 컨테이너 자신의 내부 엔트리를
    # 후미결합/은닉으로 오탐하지 않게 하고, EOCD 뒤에 붙은 진짜 후미 데이터도 포착.
    if data.startswith(b"PK\x03\x04"):
        return (doc_type or "ZIP 아카이브"), _parse_zip_natural_eof(data)
    if doc_type:
        return doc_type, size
    return "일반 바이너리", size


# =========================================================================
# 이종 미디어 카빙
# =========================================================================
def carve_embedded_media(data, carrier_fmt, natural_eof):
    """파일 전체에서 내부에 숨겨진 이미지/동영상/오디오/아카이브/PDF 시그니처를 찾아 잘라낸(carve) 항목 리스트 반환."""
    results = []
    size = len(data)
    start_search = 16 if carrier_fmt != "LSB_STREAM" else 0
    # 파일 자체가 ZIP 컨테이너(DOCX/XLSX/PPTX/HWPX/ZIP)면, 내부 엔트리로 '정상 삽입된' 미디어
    # (예: word/media/image1.png)의 시그니처가 노출돼 은닉으로 오탐된다. 이를 막기 위해 ZIP 계열은
    # 모든 미디어 카빙을 정상 종료(EOCD) 이후부터만 수행한다(EOCD 뒤에 결합된 진짜 은닉은 여전히 포착).
    zip_self = data.startswith(b"PK\x03\x04")
    base = natural_eof if zip_self else start_search

    pos = base
    while True:
        idx = data.find(b"\x89PNG\r\n\x1a\n", pos)
        if idx == -1:
            break
        iend = data.find(b"IEND\xae\x42\x60\x82", idx)
        end_idx = (iend + 8) if iend != -1 else size
        results.append({"label": "은닉 PNG 이미지", "offset": idx, "size": end_idx - idx, "data": data[idx:end_idx], "ext": ".png", "note": "PNG 시그니처 카빙"})
        pos = end_idx

    pos = natural_eof if ("JPEG" in carrier_fmt or zip_self) else start_search
    while True:
        idx = data.find(b"\xff\xd8\xff", pos)
        if idx == -1 or idx + 4 >= size:
            break
        if data[idx + 3] in (0xE0, 0xE1, 0xDB, 0xEE):
            eoi = data.find(b"\xff\xd9", idx + 4)
            if eoi != -1 and (eoi + 2 - idx) > 512:
                end_idx = eoi + 2
                results.append({"label": "은닉 JPEG 이미지", "offset": idx, "size": end_idx - idx, "data": data[idx:end_idx], "ext": ".jpg", "note": "JPEG 시그니처 카빙"})
                pos = end_idx
                continue
        pos = idx + 3

    for sig in (b"GIF89a", b"GIF87a"):
        pos = base
        while True:
            idx = data.find(sig, pos)
            if idx == -1:
                break
            if idx + 10 < size:
                end_idx = data.find(b"\x00\x3b", idx + 10)
                end_idx = (end_idx + 2) if end_idx != -1 else size
                if end_idx - idx > 64:
                    results.append({"label": "은닉 GIF 이미지", "offset": idx, "size": end_idx - idx, "data": data[idx:end_idx], "ext": ".gif", "note": "GIF 시그니처 카빙"})
                    pos = end_idx
                    continue
            pos = idx + 6

    pos = base
    while True:
        idx = data.find(b"RIFF", pos)
        if idx == -1 or idx + 12 > size:
            break
        sub_type = data[idx + 8:idx + 12]
        riff_len = struct.unpack("<I", data[idx + 4:idx + 8])[0] + 8
        if sub_type in (b"WEBP", b"AVI ", b"WAVE") and 32 < riff_len <= (size - idx + 1024):
            end_idx = min(idx + riff_len, size)
            lbl_map = {b"WEBP": ("은닉 WEBP 이미지", ".webp"), b"AVI ": ("은닉 AVI 동영상", ".avi"), b"WAVE": ("은닉 WAV 오디오", ".wav")}
            lbl, ext = lbl_map[sub_type]
            results.append({"label": lbl, "offset": idx, "size": end_idx - idx, "data": data[idx:end_idx], "ext": ext, "note": "RIFF 컨테이너 카빙"})
            pos = end_idx
        else:
            pos = idx + 4

    pos = base
    mp4_brands = (b"isom", b"mp41", b"mp42", b"avc1", b"iso2", b"M4V ", b"qt  ", b"MSNV", b"dash")
    while True:
        idx = data.find(b"ftyp", pos)
        if idx == -1 or idx < 4 or idx + 8 > size:
            break
        brand = data[idx + 4:idx + 8]
        ftyp_size = struct.unpack(">I", data[idx - 4:idx])[0]
        if brand in mp4_brands and 8 <= ftyp_size <= 128:
            start_off = idx - 4
            results.append({"label": "은닉 MP4/MOV 동영상", "offset": start_off, "size": size - start_off, "data": data[start_off:], "ext": ".mp4", "note": "ISOBMFF 동영상 카빙"})
            pos = start_off + ftyp_size
        else:
            pos = idx + 4

    for sig, label, ext in [
        (b"PK\x03\x04", "은닉 ZIP 아카이브", ".zip"),
        (b"Rar!\x1a\x07", "은닉 RAR 아카이브", ".rar"),
        (b"7z\xbc\xaf\x27\x1c", "은닉 7-Zip 아카이브", ".7z"),
        (b"%PDF-1.", "은닉 PDF 문서", ".pdf"),
    ]:
        # 컨테이너 자신이 ZIP이면 내부 엔트리를 은닉으로 오탐하지 않도록 정상 종료(EOCD) 이후부터만 탐색.
        s = base
        idx = data.find(sig, s)
        if idx != -1 and (size - idx) > 32:
            results.append({"label": label, "offset": idx, "size": size - idx, "data": data[idx:], "ext": ext, "note": "내부 아카이브/문서 카빙"})

    return results


# =========================================================================
# PDF 구조 내부 코드 추출
# =========================================================================
def _read_pdf_literal_string(data, open_paren_idx, max_len=65536):
    if data[open_paren_idx:open_paren_idx + 1] != b"(":
        return None
    depth = 0
    i = open_paren_idx
    n = len(data)
    out = bytearray()
    while i < n and (i - open_paren_idx) < max_len:
        c = data[i]
        if c == 0x5C:
            out.append(c)
            if i + 1 < n:
                out.append(data[i + 1])
            i += 2
            continue
        if c == 0x28:
            depth += 1
            if depth > 1:
                out.append(c)
            i += 1
            continue
        if c == 0x29:
            depth -= 1
            if depth == 0:
                return bytes(out)
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return None


def _decode_pdf_string(raw):
    simple = {0x6E: 0x0A, 0x72: 0x0D, 0x74: 0x09, 0x62: 0x08, 0x66: 0x0C, 0x28: 0x28, 0x29: 0x29, 0x5C: 0x5C}
    out = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c == 0x5C and i + 1 < n:
            nxt = raw[i + 1]
            if 0x30 <= nxt <= 0x37:
                j = i + 1
                digs = bytearray()
                while j < n and len(digs) < 3 and 0x30 <= raw[j] <= 0x37:
                    digs.append(raw[j])
                    j += 1
                out.append(int(bytes(digs), 8) & 0xFF)
                i = j
                continue
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
                continue
            if nxt in (0x0A, 0x0D):
                i += 2
                continue
            out.append(nxt)
            i += 2
            continue
        out.append(c)
        i += 1
    return out.decode("utf-8", errors="replace")


def _encode_pdf_string(b):
    """바이트를 PDF 리터럴 문자열 본문으로 이스케이프(\\ ( ) 와 비인쇄 바이트는 8진수)."""
    out = bytearray()
    for c in b:
        if c in (0x5C, 0x28, 0x29):
            out += b"\\" + bytes([c])
        elif 0x20 <= c < 0x7F:
            out.append(c)
        else:
            out += b"\\%03o" % c
    return bytes(out)


def _pdf_rebuild_xref(data):
    """마지막 고전 xref 테이블/trailer 를 'N G obj' 실제 위치로 다시 만들어 붙인다.
    xref 스트림(PDF 1.5+ 압축 xref)만 있는 파일은 그대로 반환(뷰어가 자동 복구)."""
    # ponytail: 'N G obj' 정규식 스캔 — 압축 안 된 스트림 안의 우연한 패턴은 오인 가능, 필요시 파서 기반으로 교체
    # 마지막 'startxref N %%EOF' 이후(후미 결합 은닉 데이터 등)는 건드리지 않고 그대로 뒤에 다시 붙인다
    ends = list(re.finditer(rb"startxref\s+\d+\s+%%EOF[ \t]*\r?\n?", data))
    if not ends:
        return data
    extra = data[ends[-1].end():]
    data = data[:ends[-1].end()]
    xrefs = list(re.finditer(rb"(?m)^xref\s", data))
    if not xrefs:
        return data + extra
    tail = data[xrefs[-1].start():]
    tm = re.search(rb"trailer\s*(<<.*>>)\s*startxref", tail, re.S)
    if not tm:
        return data + extra
    trailer = re.sub(rb"/(Prev|XRefStm)\s+\d+", b"", tm.group(1))
    body = data[:xrefs[-1].start()]
    objs = {}
    for m in re.finditer(rb"(?<![0-9])(\d+)\s+(\d+)\s+obj\b", body):
        objs[int(m.group(1))] = (m.start(), int(m.group(2)))   # 증분 업데이트면 뒤의 것이 최신
    size = max(objs) + 1 if objs else 1
    old_size = re.search(rb"/Size\s+(\d+)", trailer)
    if old_size:
        size = max(size, int(old_size.group(1)))
        trailer = trailer.replace(old_size.group(0), b"/Size %d" % size, 1)
    if not body.endswith(b"\n"):
        body += b"\n"
    rows = [b"%010d %05d n\r\n" % objs[i] if i in objs else b"0000000000 65535 f\r\n" for i in range(size)]
    return (body + b"xref\n0 %d\n" % size + b"".join(rows)
            + b"trailer\n" + trailer + b"\nstartxref\n%d\n%%%%EOF\n" % len(body) + extra)


def pdf_reinject_js(data, offset, edited):
    """offset(/JS 위치)의 스크립트를 edited 로 교체하고 xref 를 재생성한 PDF 바이트 반환.
    원래 형식(리터럴 () / 16진 <>)을 유지한다. 위치에서 /JS 를 못 찾으면 ValueError."""
    m = re.compile(rb"/JS\s*([(<])").match(data, offset)
    if not m:
        raise ValueError("해당 위치에서 /JS 문자열을 찾지 못했습니다.")
    start = m.start(1)
    if m.group(1) == b"(":
        raw = _read_pdf_literal_string(data, start)
        if raw is None:
            raise ValueError("/JS 리터럴 문자열이 닫히지 않았습니다.")
        end = start + len(raw) + 2                      # raw 는 바깥 괄호 사이 원문 그대로
        new = b"(" + _encode_pdf_string(edited) + b")"
    else:
        end = data.index(b">", start) + 1
        new = b"<" + binascii.hexlify(edited).upper() + b">"
    return _pdf_rebuild_xref(data[:start] + new + data[end:])


def extract_structural_payloads(data, carrier_fmt):
    results = []
    if not data.startswith(b"%PDF"):
        return results
    seen = set()
    for m in re.finditer(rb"/JS\s*\(", data):
        paren_idx = data.find(b"(", m.start())
        if paren_idx == -1 or paren_idx in seen:
            continue
        raw = _read_pdf_literal_string(data, paren_idx)
        if raw is None:
            continue
        seen.add(paren_idx)
        decoded = _decode_pdf_string(raw)
        results.append({
            "category": "PDF 구조 내 코드", "fmt": "JavaScript (내장 액션)",
            "offset": f"0x{m.start():X}", "data": decoded.encode("utf-8", errors="replace"),
            "detail": "PDF /JS 액션 객체 은닉 스크립트 (문서 열람 시 실행 가능)",
            "name": "pdf_embedded.js", "decoded": decoded,   # 편집·재삽입 대상 → 표시용 머리글 없이 순수 코드만
        })
    for m in re.finditer(rb"/JS\s*<([0-9A-Fa-f\s]+)>", data):
        hexs = re.sub(rb"\s+", b"", m.group(1))
        if len(hexs) % 2 != 0:
            continue
        try:
            decoded_b = binascii.unhexlify(hexs)
        except Exception:
            continue
        results.append({
            "category": "PDF 구조 내 코드", "fmt": "JavaScript (Hex 인코딩)",
            "offset": f"0x{m.start():X}", "data": decoded_b,
            "detail": "PDF /JS 액션 객체 (16진 인코딩) 은닉 스크립트",
            "name": "pdf_embedded_hex.js", "decoded": decoded_b.decode("utf-8", errors="replace"),
        })
    # 3) 기타 자동 실행/외부 호출 액션 — 주변 사전 블록을 추출해 항목화
    for pat, fmt, name in [
        (rb"/OpenAction\b", "PDF OpenAction (자동 실행)", "pdf_openaction.txt"),
        (rb"/Launch\b", "PDF Launch (외부 프로그램 실행)", "pdf_launch.txt"),
        (rb"/EmbeddedFile\b", "PDF EmbeddedFile (첨부 파일)", "pdf_embeddedfile.txt"),
    ]:
        m = re.search(pat, data)
        if not m:
            continue
        s = max(0, m.start() - 20)
        block = data[s:data.find(b">>", m.start()) + 2] if data.find(b">>", m.start()) != -1 else data[s:s + 300]
        results.append({
            "category": "PDF 구조 내 코드", "fmt": fmt,
            "offset": f"0x{m.start():X}", "data": block,
            "detail": f"{fmt} 객체 사전 블록",
            "name": name, "decoded": block.decode("latin1", errors="replace"),
        })
    return results


def extract_strings(data, min_len=4, max_count=4000):
    """바이너리에서 출력 가능한 ASCII 문자열 시퀀스를 추출한다 (strings 유틸리티 유사)."""
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
                if len(out) >= max_count:
                    return out
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return out


# =========================================================================
# 메타데이터/청크 분석
# =========================================================================
def _check_chunk_code(buf, location_label, threats, payloads=None):
    langs, _, decoded = scan_all_languages_and_deobfuscate(buf)
    if langs:
        threats.append(f"{location_label} 내부 코드 패턴 감지 ({', '.join(langs)})")
        if payloads is not None and buf:
            payloads.append({
                "category": "메타데이터 내 코드", "fmt": f"코드 패턴: {', '.join(langs[:2])}",
                "offset": location_label, "data": bytes(buf),
                "detail": f"{location_label} 청크/세그먼트 내부 은닉 코드",
                "name": "chunk_embedded.txt", "decoded": decoded,
            })


def inspect_metadata_and_chunks(data, carrier_fmt):
    """PNG 청크/JPEG 마커/PDF 액션객체/MP3 ID3/RIFF 서브청크를 파싱해 (리포트문자열, 위협목록, 코드페이로드) 반환."""
    lines = [f"=== [{carrier_fmt}] 컨테이너 청크 및 메타데이터 정밀 구조 분석 ===\n"]
    threats = []
    payloads = []          # 뷰어 항목으로 승격할 '구조 내부 코드'
    size = len(data)

    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        pos = 8
        while pos + 12 <= size:
            c_len = struct.unpack(">I", data[pos:pos + 4])[0]
            if pos + 12 + c_len > size:
                lines.append(f" [!] 비정상 청크 길이 감지 (Offset: 0x{pos:X}, Length: {c_len})")
                break
            c_type = data[pos + 4:pos + 8].decode("latin1", errors="replace")
            c_data = data[pos + 8:pos + 8 + c_len]
            lines.append(f" • PNG Chunk [{c_type}] | Offset: 0x{pos:X} | Length: {c_len:,} bytes")
            if c_type == "tEXt":
                parts = c_data.split(b"\x00", 1)
                kw = parts[0].decode("latin1", errors="replace")
                txt_bytes = parts[1] if len(parts) > 1 else b""
                lines.append(f"    -> [tEXt] Keyword: '{kw}' | Text: {txt_bytes[:160].decode('utf-8', errors='replace')}")
                _check_chunk_code(txt_bytes, f"PNG tEXt({kw})", threats, payloads)
            elif c_type == "zTXt":
                null_idx = c_data.find(b"\x00")
                if null_idx != -1 and null_idx + 2 <= len(c_data):
                    kw = c_data[:null_idx].decode("latin1", errors="replace")
                    comp_method = c_data[null_idx + 1]
                    comp_stream = c_data[null_idx + 2:]
                    try:
                        if comp_method == 0:
                            txt_bytes = crypto.safe_zlib_decompress(comp_stream)
                            lines.append(f"    -> [zTXt] Keyword: '{kw}' (압축 해제 성공: {len(txt_bytes):,} B) | 내용: {txt_bytes[:160].decode('utf-8', errors='replace')}")
                            _check_chunk_code(txt_bytes, f"PNG zTXt({kw})", threats, payloads)
                        else:
                            lines.append(f"    -> [zTXt] 알 수 없는 압축 방식 바이트: {comp_method}")
                    except Exception as e:
                        lines.append(f"    -> [zTXt] 압축 해제 실패 (손상된 스트림 또는 폭탄 차단): {e}")
                        threats.append(f"PNG zTXt({kw}) 비정상 압축 스트림 감지")
            elif c_type == "iTXt":
                null1 = c_data.find(b"\x00")
                if null1 != -1 and null1 + 3 <= len(c_data):
                    kw = c_data[:null1].decode("latin1", errors="replace")
                    comp_flag = c_data[null1 + 1]
                    comp_method = c_data[null1 + 2]
                    rest = c_data[null1 + 3:]
                    null2 = rest.find(b"\x00")
                    if null2 != -1:
                        rest2 = rest[null2 + 1:]
                        null3 = rest2.find(b"\x00")
                        if null3 != -1:
                            raw_txt_field = rest2[null3 + 1:]
                            try:
                                txt_bytes = crypto.safe_zlib_decompress(raw_txt_field) if (comp_flag == 1 and comp_method == 0) else raw_txt_field
                                lines.append(f"    -> [iTXt] Keyword: '{kw}' | 내용: {txt_bytes[:160].decode('utf-8', errors='replace')}")
                                _check_chunk_code(txt_bytes, f"PNG iTXt({kw})", threats, payloads)
                            except Exception as e:
                                lines.append(f"    -> [iTXt] 압축 해제 오류: {e}")
            pos += 12 + c_len
            if c_type == "IEND":
                break

    elif data.startswith(b"\xff\xd8\xff"):
        pos = 2
        while pos + 4 <= size and data[pos] == 0xFF:
            marker = data[pos + 1]
            if marker in (0xD9, 0xDA):
                lines.append(f" • JPEG Marker [0xFF{marker:02X}] | Offset: 0x{pos:X}")
                break
            seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            if seg_len < 2 or pos + 2 + seg_len > size:
                break
            seg_data = data[pos + 4:pos + 2 + seg_len]
            if marker == 0xFE:
                lines.append(f" • JPEG Comment (0xFFFE) | Offset: 0x{pos:X} | 내용: {seg_data[:160].decode('utf-8', errors='replace')}")
                _check_chunk_code(seg_data, "JPEG Comment(COM)", threats, payloads)
            elif marker == 0xE1:
                lines.append(f" • JPEG APP1 (EXIF/XMP) | Offset: 0x{pos:X} | Length: {seg_len:,} bytes")
                _check_chunk_code(seg_data, "JPEG EXIF(APP1)", threats, payloads)
            pos += 2 + seg_len

    elif data.startswith(b"%PDF"):
        uncommented = re.sub(rb"(?m)^\s*%[^\r\n]*", b"", data)
        dict_blocks = re.findall(rb"<<[\s\S]{1,4096}?>>", uncommented)
        dict_combined = b"\n".join(dict_blocks)
        pdf_action_rules = [
            (rb"/S\s*/JavaScript\b|/JS\s*(\(|<|[0-9]+\s+[0-9]+\s+R)", "/JavaScript 실행 액션 객체"),
            (rb"/OpenAction\s*(\[|<<|[0-9]+\s+[0-9]+\s+R)", "/OpenAction 문서 열람 시 자동 실행 객체"),
            (rb"/Launch\b", "/Launch 외부 프로그램 실행 객체"),
            (rb"/EmbeddedFiles\b|/EF\s*<<", "/EmbeddedFiles 내부 파일 첨부 객체"),
            (rb"/RichMedia\b", "/RichMedia 플래시/멀티미디어 객체"),
        ]
        for regex_pat, desc in pdf_action_rules:
            cnt = len(re.findall(regex_pat, dict_combined))
            raw_cnt = uncommented.count(desc.split()[0].encode("ascii"))
            lines.append(f" • PDF 객체 검증 [{desc}] : 실제 사전(Dictionary) 구조 매칭 {cnt}회 (단순 문자열 출현: {raw_cnt}회)")
            if cnt > 0:
                threats.append(f"PDF 실제 액션 객체 확인: {desc} ({cnt}회)")
            elif raw_cnt > 0:
                lines.append("    -> 참고: 사전 객체 외부(본문/스트림 등)에 단순 문자열이 존재하나 실행 객체 구조는 아닙니다 (오탐 배제됨).")

    elif data.startswith(b"ID3") and size >= 10:
        ver_maj, ver_min = data[3], data[4]
        s0, s1, s2, s3 = data[6], data[7], data[8], data[9]
        id3_size = ((s0 & 0x7F) << 21) | ((s1 & 0x7F) << 14) | ((s2 & 0x7F) << 7) | (s3 & 0x7F)
        lines.append(f" • MP3 ID3v2.{ver_maj}.{ver_min} 태그 영역 | 크기: {id3_size:,} bytes")
        _check_chunk_code(data[10:min(10 + id3_size, size)], "MP3 ID3v2 태그", threats, payloads)

    elif data.startswith(b"RIFF") and size >= 12:
        pos = 12
        while pos + 8 <= size:
            c_id = data[pos:pos + 4].decode("latin1", errors="replace")
            c_sz = struct.unpack("<I", data[pos + 4:pos + 8])[0]
            lines.append(f" • RIFF Subchunk [{c_id}] | Offset: 0x{pos:X} | Size: {c_sz:,} bytes")
            pos += 8 + c_sz + (c_sz % 2)

    return "\n".join(lines), threats, payloads


# =========================================================================
# LSB 반송체 검사
# =========================================================================
def inspect_lsb_carrier(raw_carrier, label_prefix, scan_pw, result, findings, sampwidth=1, quiet_if_clean=False, next_id=None):
    """raw_carrier(픽셀 또는 PCM 프레임)에서 LSB 패킷/코드 탐지. result.carved에 CarvedItem 추가."""
    found_packet = False
    pkt_len = crypto.probe_lsb_packet_length(raw_carrier, sampwidth=sampwidth)
    if pkt_len > 0:
        pkt = crypto.extract_lsb_bytes(raw_carrier, pkt_len, sampwidth=sampwidth)
        parsed = crypto.parse_packet(pkt, LSB_MAGIC, scan_pw)
        if parsed:
            found_packet = True
            ver = parsed.get("version", "v5")
            if parsed.get("encrypted_locked"):
                msg = "비밀번호 불일치 또는 파일명/헤더 위변조(HMAC 실패)" if parsed.get("wrong_password_or_tampered") else "복호화 비밀번호 필요"
                findings.append(f"[확정/CRITICAL] {label_prefix}에서 암호화 패킷({parsed['filename']}, {ver}) 탐지 [{msg}]")
                result.log_lines.append(f"  [!] 경보: {label_prefix} 암호화 패킷 발견 ({ver}) | 파일명: {parsed['filename']} ({msg})")
                _add(result, label_prefix, f"암호 잠김 ({ver})", "LSB Bit 0", pkt, f"파일명: {parsed['filename']} ({msg})", parsed["filename"])
            else:
                integ_str = "무결성 검증 통과" if parsed["integrity_ok"] else "경고: 파일명/헤더 또는 본문 위변조됨!"
                sev = "CRITICAL" if parsed["integrity_ok"] else "TAMPERED"
                findings.append(f"[확정/{sev}] {label_prefix}에서 은닉 파일({parsed['filename']}, {ver}) 복원 [{integ_str}]")
                result.log_lines.append(f"  [!] 경보: {label_prefix} 은닉 파일 복원 ({ver}) | 파일명: {parsed['filename']} ({parsed['original_size']:,} B) | {integ_str}")
                _add(result, label_prefix, f"LSB 은닉 파일 ({ver})", "LSB Bit 0", parsed["payload"], f"파일명: {parsed['filename']} ({integ_str})", parsed["filename"])

    if quiet_if_clean and not found_packet:
        return False

    max_extractable = (len(raw_carrier) // sampwidth) // 8
    sample_size = min(max_extractable, 16384)
    if sample_size > 0:
        lsb_sample = crypto.extract_lsb_bytes(raw_carrier, sample_size, sampwidth=sampwidth)
        lsb_entropy = analysis.calc_entropy(lsb_sample[:4096])
        if not quiet_if_clean:
            result.log_lines.append(f"  • {label_prefix} 평면 엔트로피 : {lsb_entropy:.3f} / 8.000")

        # 통계적 스테그분석 (우리 패킷이 아니어도 범용 LSB 은닉 흔적 탐지)
        grade, sa_msg = steganalysis.assess(raw_carrier, lsb_sample)
        if not quiet_if_clean:
            result.log_lines.append(f"  • {label_prefix} 스테그분석 : {sa_msg}")
        if grade == "HIGH":
            findings.append(f"[스테그분석/HIGH] {label_prefix} 통계적 LSB 은닉 징후 강함 ({sa_msg})")
        elif grade == "MEDIUM":
            findings.append(f"[스테그분석/MEDIUM] {label_prefix} 통계적 LSB 은닉 의심 ({sa_msg})")
        if not found_packet:
            lsb_langs, _, lsb_decoded = scan_all_languages_and_deobfuscate(lsb_sample)
            if lsb_langs:
                found_packet = True
                findings.append(f"[패턴주의/HIGH] {label_prefix} 비트 스트림 내 평문 코드 패턴 탐지 ({', '.join(lsb_langs)})")
                result.log_lines.append(f"  [!] 경보: {label_prefix} 스트림에서 코드 시그니처 탐지: {', '.join(lsb_langs)}")
                _add(result, label_prefix, ", ".join(lsb_langs[:2]), "LSB Bit 0", lsb_sample, "비압축 LSB 코드 스트림", "lsb_extracted_code.txt", lsb_decoded)
    return found_packet


_STEG_TOOL_HINTS = ("steghide", "openstego", "outguess", "stegano", "zsteg",
                    "jsteg", "silenteye", "invoke-psimage", "stegsolve", "f5")


def _gps_decimal(g):
    """EXIF GPS 딕셔너리({GPSLatitude:(d,m,s), GPSLatitudeRef:'N', ...}) → (lat, lon) 10진수. 실패 시 (None,None)."""
    def conv(vals, ref):
        try:
            d, m, s = (float(x) for x in vals)
            dec = d + m / 60.0 + s / 3600.0
            if str(ref).upper() in ("S", "W"):
                dec = -dec
            return round(dec, 6)
        except Exception:
            return None
    return conv(g.get("GPSLatitude"), g.get("GPSLatitudeRef")), conv(g.get("GPSLongitude"), g.get("GPSLongitudeRef"))


_XMP_FIELDS = [
    ("xmp:CreatorTool", "제작도구(XMP)"), ("dc:creator", "작성자(XMP)"), ("dc:rights", "저작권(XMP)"),
    ("photoshop:DateCreated", "생성일(XMP)"), ("xmp:CreateDate", "생성일시(XMP)"), ("xmp:ModifyDate", "수정일시(XMP)"),
    ("xmp:MetadataDate", "메타수정일(XMP)"), ("tiff:Make", "카메라Make(XMP)"), ("tiff:Model", "카메라Model(XMP)"),
    ("xmpMM:DocumentID", "문서ID(XMP)"), ("xmpMM:InstanceID", "인스턴스ID(XMP)"),
    ("Iptc4xmpCore:Location", "위치(XMP/IPTC)"), ("GPSLatitude", "GPS위도(XMP)"), ("GPSLongitude", "GPS경도(XMP)"),
]


def _parse_xmp(xmp):
    """XMP(RDF/XML) 패킷에서 주요 필드를 속성/엘리먼트 양쪽으로 추출. 편집 이력(xmpMM:History) 존재 여부도 보고."""
    text = xmp.decode("utf-8", "replace") if isinstance(xmp, (bytes, bytearray)) else str(xmp)
    out = []
    for field, label in _XMP_FIELDS:
        f = re.escape(field)
        m = (re.search(f + r'\s*=\s*"([^"]+)"', text) or                         # 속성형
             re.search(r"<" + f + r"[^>]*>\s*(?:<rdf:(?:Seq|Bag|Alt)[^>]*>\s*)?(?:<rdf:li[^>]*>\s*)?([^<]+)", text))  # 엘리먼트/rdf:li형
        if m and m.group(1).strip():
            out.append((label, m.group(1).strip()))
    if "xmpMM:History" in text or "stEvt:action" in text:
        out.append(("편집이력(XMP)", "존재 — 편집/변환 기록 있음"))
    return out


# 사진 편집 도구 — Software/CreatorTool에 있으면 '원본이 아님(편집본)' 포렌식 단서
_EDIT_TOOLS = ("photoshop", "gimp", "lightroom", "snapseed", "picsart", "canva", "pixlr",
               "affinity", "paint.net", "meitu", "facetune", "remini")


def _img_short(v):
    s = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
    return s.replace("\n", " ").replace("\r", " ").strip()[:120]


def exif_rows(exif):
    """PIL Exif 객체 → (행, 경보). JPEG/PNG/WebP/TIFF(PIL로 연 이미지)와 HEIC(직접 파싱) 공용.
    GPS·일련번호 등 개인식별 정보 + 촬영/수정 시각 불일치·편집 도구 흔적(포렌식)까지 경보로 표면화."""
    from PIL.ExifTags import TAGS, GPSTAGS
    import datetime
    rows, alerts = [], []
    short = _img_short
    if not exif:
        return rows, alerts
    for tid, val in exif.items():
        name = TAGS.get(tid, f"0x{tid:04X}")
        if name == "GPSInfo":
            continue
        sv = short(val)
        rows.append((name, sv))
        if name in ("Software", "ProcessingSoftware", "HostComputer") and any(t in sv.lower() for t in _STEG_TOOL_HINTS):
            alerts.append(f"제작 소프트웨어가 스테가 도구로 보임: {name}={sv}")
        elif name in ("Software", "ProcessingSoftware") and any(t in sv.lower() for t in _EDIT_TOOLS):
            alerts.append(f"편집 도구 흔적 — 원본이 아닌 편집본: {name}={sv}")
        if name in ("UserComment", "ImageDescription", "XPComment") and len(sv) >= 80:
            alerts.append(f"비정상적으로 긴 {name} (은닉 텍스트 가능): {sv[:60]}…")
    # GPS — 10진 좌표로 디코딩(실제 촬영 위치)
    try:
        gps = exif.get_ifd(0x8825)
    except Exception:
        gps = None
    if gps:
        g = {GPSTAGS.get(k, k): v for k, v in gps.items()}
        lat, lon = _gps_decimal(g)
        if lat is not None and lon is not None:
            rows.append(("GPS 좌표", f"{lat}, {lon}  (지도: https://maps.google.com/?q={lat},{lon})"))
            alerts.append(f"GPS 위치정보 포함 — 촬영 위치 노출: {lat}, {lon}")
        else:
            rows.append(("GPSInfo", short(g)))
            alerts.append("GPS 위치정보 포함 (촬영 위치 노출)")
    # EXIF 서브 IFD(0x8769) — 촬영일시/렌즈/본체일련번호/소유자 등 상세·개인식별 정보
    try:
        sub = exif.get_ifd(0x8769)
    except Exception:
        sub = {}
    _SUB = {0x9003: "촬영일시(Original)", 0x9004: "디지털화일시", 0xA434: "렌즈모델",
            0xA431: "본체일련번호", 0xA430: "카메라소유자", 0xA435: "렌즈일련번호"}
    for tid, label in _SUB.items():
        if tid in sub:
            sv = short(sub[tid])
            if sv:
                rows.append((label, sv))
                if tid in (0xA431, 0xA430, 0xA435):
                    alerts.append(f"{label}(개인식별 정보) 포함: {sv}")
    # 포렌식: 파일 수정시각(DateTime) vs 촬영시각(DateTimeOriginal)
    try:
        fmt = "%Y:%m:%d %H:%M:%S"
        mod = datetime.datetime.strptime(str(exif.get(0x0132)).strip()[:19], fmt)
        shot = datetime.datetime.strptime(str(sub.get(0x9003)).strip()[:19], fmt)
        gap = (mod - shot).total_seconds()
        if gap < -60:
            alerts.append(f"수정시각({mod})이 촬영시각({shot})보다 이름 — 시각 조작 의심")
        elif gap > 60:
            alerts.append(f"촬영 후 다시 저장됨(편집 흔적): 촬영 {shot} → 수정 {mod}")
    except (ValueError, TypeError):
        pass
    return rows, alerts


def _exif_thumbnail(raw):
    """EXIF(APP1) 바이트에서 IFD1 썸네일 JPEG 추출. 없으면 None."""
    t = raw[6:] if raw[:6] == b"Exif\x00\x00" else raw
    if t[:2] not in (b"II", b"MM"):
        return None
    e = "<" if t[:2] == b"II" else ">"
    try:
        ifd0 = struct.unpack(e + "I", t[4:8])[0]
        n = struct.unpack(e + "H", t[ifd0:ifd0 + 2])[0]
        ifd1 = struct.unpack(e + "I", t[ifd0 + 2 + 12 * n:ifd0 + 6 + 12 * n])[0]
        if not ifd1:
            return None
        tags = {}
        for i in range(struct.unpack(e + "H", t[ifd1:ifd1 + 2])[0]):
            p = ifd1 + 2 + 12 * i
            tags[struct.unpack(e + "H", t[p:p + 2])[0]] = struct.unpack(e + "I", t[p + 8:p + 12])[0]
        off, ln = tags.get(0x0201), tags.get(0x0202)
        return t[off:off + ln] if off and ln and off + ln <= len(t) else None
    except struct.error:
        return None


def thumbnail_mismatch(img):
    """포렌식: EXIF 썸네일 vs 본 이미지 비교. 편집기는 본 이미지만 바꾸고 썸네일은 원본을 남기는 경우가 많다
    → 크롭·합성·지운 흔적. 썸네일의 검은 여백(레터박스)은 잘라내고 비교. 반환: 경보[]."""
    from PIL import Image, ImageChops, ImageStat
    try:
        th = _exif_thumbnail((getattr(img, "info", {}) or {}).get("exif") or b"")
        if not th:
            return []
        t = Image.open(io.BytesIO(th)).convert("L")
        box = t.point(lambda v: 255 if v > 16 else 0).getbbox()
        if not box:
            return []
        t = t.crop(box)
        ar_t, ar_m = t.width / t.height, img.width / img.height
        if abs(ar_t - ar_m) / ar_m > 0.10:
            return [f"EXIF 썸네일 비율({t.width}x{t.height})이 본 이미지({img.width}x{img.height})와 다름 — 크롭 흔적"]
        main = img.convert("L").resize(t.size)
        diff = ImageStat.Stat(ImageChops.difference(main, t)).mean[0]
        if diff > 30:
            return [f"EXIF 썸네일과 본 이미지 내용이 다름(평균차 {diff:.0f}/255) — 편집·합성 흔적, 썸네일에 원본 잔존"]
    except Exception:
        pass
    return []


def extract_image_metadata(img):
    """PIL로 이미지 EXIF/텍스트 메타데이터를 사람이 읽을 수 있게 추출(카메라/일시/소프트웨어/GPS/코멘트).
    포렌식 단서(제작 소프트웨어가 스테가 도구, GPS 위치, 비정상 코멘트)를 표면화. 반환: (행[(키,값)], 경보[])."""
    rows, alerts = [], []
    short = _img_short
    rows.append(("크기/모드", f"{img.width}x{img.height} / {img.mode}"))
    try:
        exif = img.getexif()
    except Exception:
        exif = None
    er, ea = exif_rows(exif)
    rows += er
    alerts += ea + thumbnail_mismatch(img)

    # img.info: EXIF(APP1) 외의 메타도 표면화 — JFIF/DPI/ICC(APP0/APP2), JPEG Comment(COM), PNG 텍스트 청크 등
    info = getattr(img, "info", {}) or {}
    if info.get("dpi"):
        rows.append(("DPI", short(info["dpi"])))
    if info.get("jfif_version"):
        rows.append(("JFIF 버전", short(info["jfif_version"])))
    if info.get("icc_profile"):
        icc = info["icc_profile"]
        desc = icc[0x34:0x34 + 60].split(b"\x00", 1)[0].decode("latin1", "replace") if len(icc) > 0x40 else ""
        rows.append(("ICC 프로파일", f"{len(icc):,} bytes" + (f" | {desc}" if desc.isprintable() and desc.strip() else "")))
    comment = info.get("comment")
    if comment:
        cv = short(comment)
        rows.append(("Comment(COM)", cv))
        if len(cv) >= 80 or any(t in cv.lower() for t in _STEG_TOOL_HINTS):
            alerts.append(f"의심 Comment(COM): {cv[:60]}")
    # XMP(Adobe RDF) 패킷 — 제작도구/작성자/편집이력 등 파싱
    xmp = info.get("xmp") or info.get("XML:com.adobe.xmp")
    if xmp:
        for label, val in _parse_xmp(xmp):
            rows.append((label, short(val)))
            if any(t in val.lower() for t in _STEG_TOOL_HINTS):
                alerts.append(f"XMP '{label}'에 스테가 도구 흔적: {val[:60]}")
            elif label == "제작도구(XMP)" and any(t in val.lower() for t in _EDIT_TOOLS):
                alerts.append(f"편집 도구 흔적(XMP) — 원본이 아닌 편집본: {val[:60]}")

    _SKIP = ("exif", "icc_profile", "dpi", "jfif", "jfif_version", "jfif_unit", "jfif_density",
             "comment", "transparency", "gamma", "srgb", "chromaticity", "background",
             "aspect", "progression", "progressive", "optimize", "adobe", "adobe_transform",
             "xmp", "xml:com.adobe.xmp", "compression", "loop", "duration")
    for k, v in info.items():
        if k.lower() in _SKIP:
            continue
        if isinstance(v, (str, bytes)):
            sv = short(v)
            rows.append((f"text:{k}", sv))
            if any(t in sv.lower() for t in _STEG_TOOL_HINTS):
                alerts.append(f"텍스트 메타 '{k}'에 스테가 도구 흔적: {sv[:60]}")
    return rows, alerts


def _meta_short(v):
    s = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
    return s.replace("\n", " ").replace("\r", " ").strip()[:160]


# PDF /Info에서 읽고/지우는 키 — metaedit 스크럽과 공유 (MS Office 내보내기는 Company/SourceModified도 남김)
PDF_INFO_KEYS = ("Title", "Author", "Subject", "Creator", "Producer", "CreationDate", "ModDate",
                 "Keywords", "Company", "SourceModified")


def _synchsafe(b):
    """ID3 synchsafe 정수(바이트당 7비트) 디코딩."""
    return ((b[0] & 0x7f) << 21) | ((b[1] & 0x7f) << 14) | ((b[2] & 0x7f) << 7) | (b[3] & 0x7f)


def id3_frames(data):
    """ID3v2.3/2.4 태그 파싱 → (버전, 오디오 시작 오프셋, [(프레임ID, 플래그2B, payload)]).
    v2.4는 프레임 크기도 synchsafe, 확장 헤더·푸터 반영. 태그 없거나 v2.2면 (0, 0 또는 끝, [])."""
    if data[:3] != b"ID3" or len(data) < 10:
        return 0, 0, []
    ver, flags = data[3], data[5]
    start = 10 + _synchsafe(data[6:10]) + (10 if flags & 0x10 else 0)   # 0x10 = 푸터 존재
    if ver not in (3, 4):
        return ver, start, []
    end = min(10 + _synchsafe(data[6:10]), len(data))
    pos = 10
    if flags & 0x40:                                                    # 확장 헤더 건너뛰기
        pos += _synchsafe(data[10:14]) if ver == 4 else 4 + int.from_bytes(data[10:14], "big")
    frames = []
    while pos + 10 <= end:
        fid = data[pos:pos + 4]
        fsize = _synchsafe(data[pos + 4:pos + 8]) if ver == 4 else int.from_bytes(data[pos + 4:pos + 8], "big")
        if not fid.isalnum() or fsize <= 0 or pos + 10 + fsize > end:   # 패딩(0x00) 또는 깨짐 → 종료
            break
        frames.append((fid, data[pos + 8:pos + 10], data[pos + 10:pos + 10 + fsize]))
        pos += 10 + fsize
    return ver, start, frames


# 표시·편집 대상 ID3 프레임 (metaedit 편집 키와 공유)
ID3_LABELS = {b"TIT2": "제목", b"TPE1": "아티스트", b"TALB": "앨범", b"TENC": "인코더",
              b"TSSE": "인코딩SW", b"COMM": "코멘트", b"TCON": "장르", b"TYER": "연도", b"TDRC": "녹음일시"}


def id3_text(fid, payload):
    """ID3 텍스트 프레임 디코딩(인코딩 바이트 0=latin1,1=UTF-16 BOM,2=UTF-16BE,3=UTF-8). COMM은 언어·설명 건너뜀."""
    if not payload:
        return ""
    enc, body = payload[0], payload[1:]
    codec = {0: "latin1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}.get(enc, "latin1")
    if fid == b"COMM":
        body = body[3:]                                              # 언어 코드 3바이트
        sep = b"\x00\x00" if enc in (1, 2) else b"\x00"
        k = body.find(sep)                                           # 짧은 설명 \0 종료 → 본문
        while enc in (1, 2) and k != -1 and k % 2:                   # UTF-16은 짝수 위치 경계만
            k = body.find(sep, k + 1)
        body = body[k + len(sep):] if k != -1 else body
    try:
        return body.decode(codec, "replace").replace("\x00", " ").strip()
    except Exception:
        return ""


HEIF_BRANDS = {b"heic", b"heix", b"heim", b"heis", b"mif1", b"msf1", b"avif", b"avis"}


def iso_boxes(d, i, end):
    """ISO BMFF(MP4/HEIF) 박스 순회 → (타입, 내용시작, 박스끝). 64비트 크기·size 0(끝까지) 처리, 깨지면 중단."""
    while i + 8 <= end:
        size, typ, hdr = int.from_bytes(d[i:i + 4], "big"), bytes(d[i + 4:i + 8]), 8
        if size == 1:
            size, hdr = int.from_bytes(d[i + 8:i + 16], "big"), 16
        elif size == 0:
            size = end - i
        if size < hdr or i + size > end:
            return
        yield typ, i + hdr, i + size
        i += size


def heif_meta_items(d):
    """HEIF/AVIF meta 박스(iinf+iloc) → {'Exif': [(파일오프셋, 길이)], 'XMP': [...]}.
    construction_method 0(파일 오프셋)만 지원 — idat 내장(1)은 드물어 건너뜀."""
    out = {}
    for typ, s, e in iso_boxes(d, 0, len(d)):
        if typ != b"meta":
            continue
        kinds, locs = {}, {}
        for t2, s2, e2 in iso_boxes(d, s + 4, e):            # meta는 FullBox(버전·플래그 4B)
            q = s2 + 4
            v = d[s2]

            def rd(n):
                nonlocal q
                val = int.from_bytes(d[q:q + n], "big")
                q += n
                return val

            if t2 == b"iinf":
                rd(2 if v == 0 else 4)                         # entry_count
                for t3, s3, e3 in iso_boxes(d, q, e2):
                    if t3 != b"infe" or d[s3] < 2:
                        continue
                    iw = 2 if d[s3] == 2 else 4
                    iid = int.from_bytes(d[s3 + 4:s3 + 4 + iw], "big")
                    p = s3 + 4 + iw + 2                         # item_protection_index 건너뜀
                    itype = d[p:p + 4]
                    if itype == b"Exif":
                        kinds[iid] = "Exif"
                    elif itype == b"mime":
                        name_end = d.find(b"\x00", p + 4, e3)
                        if name_end != -1 and b"rdf+xml" in d[name_end + 1:e3]:
                            kinds[iid] = "XMP"
            elif t2 == b"iloc":
                b1, b2 = rd(1), rd(1)
                osz, lsz, bsz, isz = b1 >> 4, b1 & 15, b2 >> 4, (b2 & 15) if v in (1, 2) else 0
                for _ in range(rd(2 if v < 2 else 4)):
                    iid = rd(2 if v < 2 else 4)
                    method = rd(2) & 15 if v in (1, 2) else 0
                    rd(2)                                       # data_reference_index
                    base = rd(bsz)
                    ext = []
                    for _ in range(rd(2)):
                        rd(isz)
                        off, ln = rd(osz), rd(lsz)
                        if ln:
                            ext.append((base + off, ln))
                    if method == 0:
                        locs[iid] = ext
        for iid, kind in kinds.items():
            out.setdefault(kind, []).extend(locs.get(iid, []))
    return out


def riff_chunks(d):
    """RIFF(WAV/WebP) 하위 청크 → [(fourcc, 청크시작, 데이터시작, 데이터끝)]. 홀수 크기는 1바이트 패딩."""
    out, i = [], 12
    while i + 8 <= len(d):
        n = int.from_bytes(d[i + 4:i + 8], "little")
        end = min(i + 8 + n, len(d))
        out.append((d[i:i + 4], i, i + 8, end))
        i = i + 8 + n + (n & 1)
    return out


def _pdf_meta_pikepdf(data):
    """pikepdf(선택 의존성)로 /Info 전체 키 + 압축된 XMP까지 읽기. 없거나 실패하면 []."""
    try:
        import pikepdf
    except ImportError:
        return []
    try:
        with pikepdf.open(io.BytesIO(data)) as pdf:
            out = [(str(k).lstrip("/"), str(v)) for k, v in pdf.docinfo.items()]
            md = pdf.Root.get("/Metadata")
            if md is not None:
                out += _parse_xmp(md.read_bytes())
            return out
    except Exception:
        return []


def _pdf_forensics(data):
    """PDF 수정 흔적: 증분 업데이트 횟수, 판마다 다른 Producer, ModDate < CreationDate."""
    alerts = []
    revs = data.count(b"startxref") - (1 if b"/Linearized" in data[:2048] else 0)
    if revs > 1:
        alerts.append(f"증분 업데이트 {revs - 1}회 — 저장 후 수정됨, 이전 판(지운 내용·옛 메타)이 파일에 잔존 가능")
    prods = [p for p in dict.fromkeys(x.strip() for x in re.findall(rb"/Producer\s*\(((?:[^()\\]|\\.)*)\)", data)) if p]
    if len(prods) > 1:
        alerts.append("판마다 Producer가 다름(다른 프로그램으로 수정): " + " → ".join(p.decode("latin1")[:40] for p in prods))
    c = re.findall(rb"/CreationDate\s*\(D:(\d{4,14})", data)
    m = re.findall(rb"/ModDate\s*\(D:(\d{4,14})", data)
    if c and m and m[-1].ljust(14, b"0") < c[-1].ljust(14, b"0"):
        alerts.append(f"ModDate({m[-1].decode()})가 CreationDate({c[-1].decode()})보다 이름 — 시각 조작 의심")
    return alerts


def _zip_forensics(z, meta):
    """OOXML/HWPX 수정 흔적: 수정일 < 작성일, ZIP 엔트리 중 일부만 저장 시각이 다름(외부 도구 삽입·수정)."""
    import datetime
    from collections import Counter
    alerts = []
    for c_key, m_key in (("created", "modified"), ("hwpx:CreatedDate", "hwpx:ModifiedDate")):
        c, m = meta.get(c_key, ""), meta.get(m_key, "")
        if c and m and m < c:
            alerts.append(f"수정일({m})이 작성일({c})보다 이름 — 시각 조작 의심")
    infos = z.infolist()
    if len(infos) >= 3:
        common = Counter(i.date_time for i in infos).most_common(1)[0][0]
        base = datetime.datetime(*common)
        odd = [i.filename for i in infos
               if abs((datetime.datetime(*i.date_time) - base).total_seconds()) > 60]
        if odd and len(odd) <= len(infos) // 2:
            alerts.append(f"ZIP 내부 일부 파트만 저장 시각이 다름 — 외부 도구로 수정/삽입 흔적: {odd[:5]}")
    return alerts


def extract_file_metadata(data):
    """이미지 외 파일(PDF/OOXML/MP3/MP4)의 사람이 읽는 메타데이터(작성자/소프트웨어/일시/제목) 추출.
    내용(매직바이트)으로 포맷 판별 → 위장 확장자여도 동작. 반환: (행[(키,값)], 경보[])."""
    rows, alerts = [], []
    short = _meta_short

    # PDF: /Info 딕셔너리 (리터럴/16진 문자열 모두). 증분 업데이트 반영 위해 '마지막' occurrence를 읽는다.
    if data[:5] == b"%PDF-":
        for key in (k.encode() for k in PDF_INFO_KEYS):
            lits = re.findall(rb"/" + key + rb"\s*\(((?:[^()\\]|\\.)*)\)", data)
            if lits:
                val = lits[-1].replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
                sv = short(val)
                if sv:
                    rows.append((key.decode(), sv))
                continue
            hexes = re.findall(rb"/" + key + rb"\s*<([0-9A-Fa-f]*)>", data)
            if hexes:
                try:
                    raw = bytes.fromhex(hexes[-1].decode())
                    # PDF 16진 텍스트: FEFF BOM이면 UTF-16BE, 아니면 PDFDocEncoding(≈latin1/UTF-8)
                    hv = short(raw[2:].decode("utf-16-be", "replace") if raw[:2] == b"\xfe\xff" else raw)
                    hv = hv.replace("\x00", "").strip()
                    if hv:
                        rows.append((key.decode(), hv))
                except Exception:
                    pass
        # XMP 메타데이터 스트림(비압축일 때만 평문으로 보임) — /Info와 별개로 작성자·제작도구·편집이력이 남는 곳
        for xm in re.finditer(rb"<x:xmpmeta\b.*?</x:xmpmeta>", data, re.S):
            for label, val in _parse_xmp(xm.group(0)):
                if val.strip():
                    rows.append((label, short(val)))
        # pikepdf(선택)가 있으면 압축 객체 스트림 안의 /Info·XMP와 비표준 키까지 보강 (정규식 결과에 없는 것만 추가)
        seen = {k for k, _ in rows}
        for k, v in _pdf_meta_pikepdf(data):
            if k not in seen and v:
                rows.append((k, short(v)))
                seen.add(k)
        blob = " ".join(v for _, v in rows).lower()
        if any(t in blob for t in _STEG_TOOL_HINTS):
            alerts.append("PDF 제작 소프트웨어가 스테가/의심 도구")
        alerts += _pdf_forensics(data)

    # OOXML(docx/xlsx/pptx) = ZIP 내부 docProps
    elif data[:4] == b"PK\x03\x04":
        import zipfile
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            names = set(z.namelist())
            specs = [("docProps/core.xml", ("dc:creator", "cp:lastModifiedBy", "dcterms:created",
                                            "dcterms:modified", "dc:title", "cp:revision")),
                     ("docProps/app.xml", ("Application", "Company", "AppVersion", "Template"))]
            for part, tags in specs:
                if part in names:
                    xml = z.read(part).decode("utf-8", "replace")
                    for tag in tags:
                        m = re.search(r"<" + re.escape(tag) + r"[^>]*>(.*?)</" + re.escape(tag) + r">", xml, re.S)
                        if m and m.group(1).strip():
                            rows.append((tag.split(":")[-1], short(m.group(1))))
            # 사용자 정의 문서 속성(custom.xml) — 내부 사용자명/경로/분류 등 민감정보가 담기는 곳
            if "docProps/custom.xml" in names:
                cxml = z.read("docProps/custom.xml").decode("utf-8", "replace")
                for pm in re.finditer(r'<property[^>]*\bname="([^"]+)"[^>]*>\s*<[^>]+>([^<]*)</', cxml):
                    val = pm.group(2).strip()
                    if val:
                        rows.append((f"custom:{pm.group(1)}", short(val)))
            # HWPX(한글) — 작성자·마지막 저장자·작성/수정일은 OPF 패키지(Contents/content.hpf)에 있음
            if "Contents/content.hpf" in names:
                hpf = z.read("Contents/content.hpf").decode("utf-8", "replace")
                for m in re.finditer(r"<(?:\w+:)?(title|creator|subject|description)\b[^>]*>([^<]*)<", hpf):
                    if m.group(2).strip():
                        rows.append((f"hwpx:{m.group(1)}", short(m.group(2))))
                for m in re.finditer(r'<(?:\w+:)?meta\b[^>]*\bname="([^"]+)"[^>]*>([^<]*)<', hpf):
                    if m.group(2).strip():
                        rows.append((f"hwpx:{m.group(1)}", short(m.group(2))))
            alerts += _zip_forensics(z, dict(rows))
        except Exception as e:
            rows.append(("파싱오류(OOXML)", short(str(e))))

    # MP3: ID3v2 텍스트 프레임
    elif data[:3] == b"ID3":
        try:
            for fid, fl, payload in id3_frames(data)[2]:
                if fid in ID3_LABELS and not fl[1]:          # 압축/암호화 등 포맷 플래그 프레임은 해석 불가
                    txt = id3_text(fid, payload)
                    if txt:
                        rows.append((ID3_LABELS[fid], short(txt)))
        except Exception as e:
            rows.append(("파싱오류(ID3)", short(str(e))))

    # HEIC/AVIF(아이폰 기본 사진) — meta 박스의 Exif/XMP 아이템을 직접 찾아 PIL Exif로 해석(플러그인 불필요)
    elif len(data) >= 12 and data[4:8] == b"ftyp" and data[8:12] in HEIF_BRANDS:
        try:
            from PIL import Image
            items = heif_meta_items(data)
            for off, ln in items.get("Exif", [])[:1]:
                raw = data[off:off + ln]
                ex = Image.Exif()
                ex.load(raw[4 + int.from_bytes(raw[:4], "big"):])   # 앞 4B = TIFF 헤더까지의 오프셋
                r, a = exif_rows(ex)
                rows += r
                alerts += a
            for off, ln in items.get("XMP", []):
                rows += [(k, short(v)) for k, v in _parse_xmp(data[off:off + ln])]
        except Exception as e:
            rows.append(("파싱오류(HEIF)", short(str(e))))

    # MP4/MOV: udta의 ©nam/©too 등 아톰
    elif len(data) >= 12 and data[4:8] == b"ftyp":
        for tag, label in ((b"\xa9nam", "제목"), (b"\xa9ART", "아티스트"), (b"\xa9too", "인코더"),
                           (b"\xa9day", "날짜"), (b"\xa9cmt", "코멘트"), (b"\xa9alb", "앨범")):
            i = data.find(tag)
            if i != -1:
                seg = data[i + 4:i + 300]
                m = re.search(rb"data.{8}([\x20-\x7e]{2,})", seg) or re.search(rb"([\x20-\x7e]{3,})", seg)
                if m:
                    rows.append((label, short(m.group(1))))
        # 촬영 위치: ©xyz(안드로이드/QuickTime) 또는 Apple location.ISO6709 — "+37.5665+126.9780/" 형식
        m = re.search(rb"[+-]\d{1,2}\.\d{2,}[+-]\d{1,3}\.\d{2,}(?:[+-]\d+(?:\.\d+)?)?/", data)
        if m:
            rows.append(("촬영 위치(GPS)", m.group(0).decode()))
            alerts.append(f"동영상에 GPS 위치정보 포함 — 촬영 위치 노출: {m.group(0).decode()}")
        blob = " ".join(v for _, v in rows).lower()
        if any(t in blob for t in _STEG_TOOL_HINTS):
            alerts.append("동영상 메타에 스테가/의심 도구 흔적")

    # WAV: LIST/INFO(제목·작성자·소프트웨어), BWF bext(녹음장비·일시), id3 청크, XMP(_PMX)
    elif data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        INFO = {b"INAM": "제목", b"IART": "아티스트", b"ICMT": "코멘트", b"ICRD": "생성일", b"ISFT": "소프트웨어",
                b"IENG": "엔지니어", b"ICOP": "저작권", b"IPRD": "앨범"}
        for cid, _, s, e in riff_chunks(data):
            if cid == b"LIST" and data[s:s + 4] == b"INFO":
                j = s + 4
                while j + 8 <= e:
                    sid, n = data[j:j + 4], int.from_bytes(data[j + 4:j + 8], "little")
                    val = data[j + 8:j + 8 + n].split(b"\x00")[0]
                    if sid in INFO and val.strip():
                        rows.append((INFO[sid], short(val)))
                    j += 8 + n + (n & 1)
            elif cid == b"bext":
                for a, z_, label in ((0, 256, "BWF 설명"), (256, 288, "BWF 녹음장비"), (288, 320, "BWF 참조ID"),
                                     (320, 330, "BWF 녹음일"), (330, 338, "BWF 녹음시각")):
                    val = data[s + a:s + z_].split(b"\x00")[0]
                    if val.strip():
                        rows.append((label, short(val)))
            elif cid in (b"id3 ", b"ID3 "):
                for fid, fl, p in id3_frames(data[s:e])[2]:
                    if fid in ID3_LABELS and not fl[1] and id3_text(fid, p):
                        rows.append((ID3_LABELS[fid], short(id3_text(fid, p))))
            elif cid == b"_PMX":
                rows += [(k, short(v)) for k, v in _parse_xmp(data[s:e])]
            elif cid == b"iXML":
                rows.append(("iXML(녹음기 메타)", f"{e - s:,} bytes"))

    return rows, alerts


def _image_steganalysis(img, file_bytes, ext, findings, emit, label="픽셀"):
    """
    이미지 메타데이터(EXIF/텍스트) + RS·WS(은닉률 추정) + 띠별 국소 WS(소량 순차 은닉)
    + HCF-COM(±1 LSB matching, 참고) + 다중 순서 LSB 스캔(zsteg 방식) + JPEG이면 DCT 계수 기반 JSteg/F5 탐지.
    """
    pixels = img.tobytes()
    w, h = img.size
    pre = "" if label == "픽셀" else f"[{label}] "

    # 이미지 메타데이터(EXIF/텍스트 청크) — 포렌식 단서 표면화(PNG·JPEG 공통)
    try:
        meta_rows, meta_alerts = extract_image_metadata(img)
        if meta_rows:
            suffix = "" if len(meta_rows) > 1 else " (EXIF/텍스트 메타 없음)"
            emit(f"  • 이미지 메타데이터 ({len(meta_rows)}개 필드){suffix}:")
            for k, v in meta_rows[:30]:
                emit(f"      {k}: {v}")
        for a in meta_alerts:
            findings.append(f"[메타데이터/MEDIUM] {pre}{a}")
            emit(f"  [!] 메타데이터 경보: {a}")
    except Exception as e:
        emit(f"  [-] 메타데이터 추출 예외: {e}")
    # 공간 도메인(픽셀) 통계·ML 분석은 무손실 포맷에만 유효. JPEG은 IDCT 양자화 노이즈가
    # RS/WS/HCF/ML 오탐을 유발하므로 건너뛰고 아래 DCT 계수 분석(JSteg/F5)만 수행한다.
    if ext not in (".jpg", ".jpeg"):
        rate = steganalysis.rs_analysis(pixels)
        emit(f"  • RS 분석 추정 은닉률 : {rate:.3f} (0=정상, 1=전 픽셀 LSB 사용)")
        if rate >= 0.35:
            findings.append(f"[스테그분석/HIGH] {pre}RS 분석: LSB 은닉률 {rate:.0%} 추정 (무작위 위치 은닉 포함)")
        elif rate >= 0.15:
            findings.append(f"[스테그분석/MEDIUM] {pre}RS 분석: LSB 은닉률 {rate:.0%} 추정")

        ws, bands = steganalysis.ws_analysis(pixels, w, h)
        emit(f"  • WS 분석 추정 은닉률 : {ws:.3f} | 띠별: " + " ".join(f"{b[2]:.2f}" for b in bands))
        if ws >= 0.1 and rate < 0.15:
            findings.append(f"[스테그분석/MEDIUM] {pre}WS 분석: 소량 LSB 은닉 {ws:.0%} 추정")
        if bands:
            top = max(bands, key=lambda b: b[2])
            rest = sorted(b[2] for b in bands if b is not top)
            med = rest[len(rest) // 2] if rest else 0.0
            if top[2] >= 0.12 and top[2] >= 4 * max(med, 0.02):
                findings.append(f"[스테그분석/MEDIUM] {pre}국소 LSB 은닉 의심: {top[0]}~{top[1]}행 구간 추정 {top[2]:.0%} (다른 구간 중앙값 {med:.0%})")

        hcf = steganalysis.lsb_matching_score(pixels, w, h)
        if hcf is not None:
            emit(f"  • HCF-COM 보정비(±1 LSB matching) : {hcf:.3f} (참고: 낮을수록 의심, 이미지마다 기준 상이)")
            if hcf < 0.75:
                findings.append(f"[스테그분석/LOW] {pre}±1 LSB matching 가능성 (HCF-COM 보정비 {hcf:.2f}) - 원본 대조 권장")

        for label, what, preview in steganalysis.multi_order_lsb_scan(pixels, w, h):
            txt = preview[:48].decode("latin-1").encode("unicode_escape").decode("ascii")
            findings.append(f"[스테그분석/HIGH] {pre}비트 배치 [{label}]에서 {what} 발견")
            emit(f"  [!] 다중 순서 LSB 스캔: [{label}] {what} | 미리보기: {txt}")

        if ml.available():
            try:
                res = ml.predict(img)
            except Exception as e:
                res = None
                emit(f"  [-] ML 스테그분석 예외: {e}")
            if res:
                prob, info = res
                emit(f"  • ML 스테그분석 은닉 확률 : {prob:.3f} — {info}")
                if prob >= 0.9:
                    findings.append(f"[ML/HIGH] {pre}학습 분류기: 적응형/±1 은닉 확률 {prob:.0%}")
                elif prob >= 0.75:
                    findings.append(f"[ML/MEDIUM] {pre}학습 분류기: 은닉 가능성 {prob:.0%}")
        return
    blocks = steganalysis.jpeg_dct_coefficients(file_bytes)
    if not blocks:
        emit("  • JPEG DCT 분석 : 건너뜀 (산술부호화/lossless 등 미지원 JPEG)")
        return
    p = steganalysis.jsteg_chi_square(blocks)
    beta = steganalysis.f5_beta(file_bytes)
    beta_txt = f"{beta:.3f}" if beta is not None else "계산 불가"
    emit(f"  • JPEG DCT 분석 : 블록 {len(blocks):,}개 | JSteg 카이제곱={p:.3f} | F5 β={beta_txt}")
    if p >= 0.95:
        findings.append(f"[스테그분석/HIGH] JPEG DCT 계수 LSB 평탄화 (JSteg/OutGuess 계열 의심, p={p:.3f})")
    elif p >= 0.8:
        findings.append(f"[스테그분석/MEDIUM] JPEG DCT 계수 LSB 평탄화 가능성 (JSteg 계열, p={p:.3f})")
    if beta is not None and beta >= 0.25:
        findings.append(f"[스테그분석/HIGH] JPEG F5 은닉 의심 (보정 β={beta:.2f})")
    elif beta is not None and beta >= 0.15:
        findings.append(f"[스테그분석/MEDIUM] JPEG F5 은닉 가능성 (보정 β={beta:.2f})")
    # JPEG 전용 ML(DCTR) — 적응형 JPEG 은닉(J-UNIWARD/UERD)·nsF5. 학습 QF 밖이면 판정 생략
    if ml.jpeg_available():
        try:
            prob, info = ml.predict_jpeg(file_bytes)
        except Exception as e:
            prob, info = None, f"예외: {e}"
        if prob is None:
            emit(f"  • JPEG ML 스테그분석 : 건너뜀 ({info})")
        else:
            emit(f"  • JPEG ML 스테그분석 은닉 확률 : {prob:.3f} — {info}")
            if prob >= 0.9:
                findings.append(f"[ML/HIGH] {pre}JPEG 분류기: 적응형/nsF5 은닉 확률 {prob:.0%}")
            elif prob >= 0.75:
                findings.append(f"[ML/MEDIUM] {pre}JPEG 분류기: 은닉 가능성 {prob:.0%}")


def _video_frames(path, findings, emit):
    """무손실 코덱 영상이면 키프레임을 추출해 이미지 스테그분석을 적용."""
    if not video.ffmpeg_exe():
        emit("  [-] ffmpeg가 없어 영상 프레임 분석을 건너뜁니다 (pip install imageio-ffmpeg).")
        return
    codec = video.probe_codec(path)
    if not codec:
        emit("  [-] 영상 코덱을 판별할 수 없습니다.")
        return
    if codec not in video.LOSSLESS_CODECS:
        emit(f"  • 영상 코덱 [{codec}] = 손실 압축 → 픽셀 LSB가 보존되지 않아 프레임 LSB 분석 생략 (컨테이너 검사는 [4-D])")
        return
    emit(f"  • 영상 코덱 [{codec}] = 무손실 → 키프레임 추출 후 이미지 스테그분석 적용")
    tmp, frames = video.extract_keyframes(path)
    try:
        for i, fp in enumerate(frames, 1):
            fimg = Image.open(fp).convert("RGB")
            emit(f"  ─ 키프레임 {i} ({fimg.size[0]}x{fimg.size[1]})")
            _image_steganalysis(fimg, b"", ".png", findings, emit, label=f"키프레임 {i}")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def _audio_steganalysis(raw_audio, sampwidth, nchannels, findings, emit):
    """WAV 에코 은닉 / 위상 코딩 탐지."""
    samples = steganalysis.pcm_to_mono(raw_audio, sampwidth, nchannels)
    z, lag = steganalysis.echo_hiding_score(samples)
    ratio, seglen = steganalysis.phase_coding_score(samples)
    emit(f"  • 에코/위상 분석 : 자기상관 피크 z={z:.1f} @지연 {lag}샘플 | ±π/2 위상 집중률={ratio:.2f} (세그먼트 {seglen})")
    if z >= 10:
        findings.append(f"[스테그분석/MEDIUM] 에코 은닉 의심 (지연 {lag}샘플에 고립 상관 피크, z={z:.1f})")
    if ratio >= 0.4:
        findings.append(f"[스테그분석/HIGH] 위상 코딩 은닉 의심 (첫 {seglen}샘플 위상 {ratio:.0%}가 ±π/2)")
    elif ratio >= 0.25:
        findings.append(f"[스테그분석/MEDIUM] 위상 코딩 은닉 가능성 (±π/2 집중률 {ratio:.0%})")


def _add(result, category, fmt, offset, data, detail, name, decoded=None):
    item = CarvedItem(category=category, format=fmt, offset=offset, data=data, detail=detail, name=name, decoded_text=decoded)
    item.id = len(result.carved) + 1
    result.carved.append(item)
    return item


# =========================================================================
# 메인 스캔 오케스트레이터
# =========================================================================
def _effective_ext(data, path):
    """내용(매직바이트) 기반 실제 유형 확장자. 파일명이 없거나 .unknown 등으로 위장돼도 픽셀/오디오/비디오
    스테가분석 분기가 돌도록 한다. 매칭 없으면 파일명 확장자로 폴백."""
    d = data[:16]
    if d[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if d[:2] == b"BM":
        return ".bmp"
    if d[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if d[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    if d[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return ".wav"
    if d[4:8] == b"ftyp":
        return ".mp4"
    if d[:4] == b"\x1aE\xdf\xa3":
        return ".mkv"
    return os.path.splitext(path)[1].lower()


def obfuscated_blob_score(data, sample=200000):
    """단일 초장문 라인 + 공백 거의 없음 + 제한된 인쇄가능 알파벳 = 난독/인코딩된 페이로드 블롭 의심.
    자연어·코드는 공백/개행이 많아 걸러지고, 코드 시그니처가 잡힌 경우(미니파이 JS 등)는 호출부에서 제외한다.
    반환: (의심여부, 설명)."""
    if len(data) < 2000:
        return False, ""
    d = data[:sample]
    printable = sum(1 for b in d if 0x20 <= b < 0x7f or b in (9, 10, 13))
    if printable / len(d) < 0.95:                 # 바이너리 → 대상 아님
        return False, ""
    ws = sum(1 for b in d if b in (9, 10, 13, 32))
    ws_ratio = ws / len(d)
    longest = max((len(ln) for ln in d.split(b"\n")), default=0)   # 샘플(앞 200KB) 내에서만 계산 — 전체 split 금지
    alphabet = {b for b in d if 0x20 <= b < 0x7f}
    if longest >= 3000 and ws_ratio < 0.02 and 16 <= len(alphabet) <= 90:
        return True, (f"난독/인코딩 블롭 의심: 최장라인 {longest:,}자, 공백 {ws_ratio:.1%}, "
                      f"알파벳 {len(alphabet)}종 (자연어/코드 아님 — 인코딩된 페이로드 가능)")
    return False, ""


def scan_file(target_path, password="", log=None):
    """
    파일을 포렌식 스캔하고 ScanResult를 반환한다.
    log: 선택적 콜백 (str) — 실시간 로그 스트리밍용. None이면 result.log_lines만 채움.
    """
    result = ScanResult()

    def emit(msg):
        result.log_lines.append(msg)
        if log:
            log(msg)

    if not os.path.isfile(target_path):
        raise FileNotFoundError(target_path)
    if os.path.getsize(target_path) > MAX_SCAN_FILE_BYTES:
        raise ValueError(f"파일 크기가 안전 상한선({MAX_SCAN_FILE_BYTES:,} B)을 초과합니다.")

    with open(target_path, "rb") as f:
        file_bytes = f.read()

    result.file_bytes = file_bytes
    result.filepath = target_path
    result.filename = os.path.basename(target_path)
    result.filesize = len(file_bytes)
    result.sha256 = hashlib.sha256(file_bytes).hexdigest()
    result.md5 = hashlib.md5(file_bytes).hexdigest()
    result.sha1 = hashlib.sha1(file_bytes).hexdigest()
    carrier_fmt, natural_eof = identify_carrier_and_eof(file_bytes)
    result.carrier_fmt = carrier_fmt
    result.natural_eof = natural_eof
    result.overall_entropy = analysis.calc_entropy(file_bytes)

    emit("=" * 72)
    emit(f" [포렌식 보안 정밀 분석 v5.0] {result.filename}")
    emit("=" * 72)
    emit(f" • 크기 / 포맷   : {result.filesize:,} bytes ({carrier_fmt})")
    emit(f" • 정상 종료지점 : 0x{natural_eof:X} ({natural_eof:,} bytes)")
    emit(f" • 전체 엔트로피 : {result.overall_entropy:.3f} / 8.000")
    emit(f" • SHA-256       : {result.sha256}\n")

    findings = result.findings

    # [1] EOF 패킷 & 후미 데이터
    emit("[1] 컨테이너 구조 및 다중 EOF 시그니처 / 후미 데이터 분석")
    eof_offsets = crypto.find_all_offsets(file_bytes, EOF_MAGIC)
    valid_eof_packets = 0
    for eof_pos in eof_offsets:
        parsed = crypto.parse_packet(file_bytes[eof_pos:], EOF_MAGIC, password)
        if parsed:
            valid_eof_packets += 1
            ver = parsed.get("version", "v5")
            if parsed.get("encrypted_locked"):
                status_msg = ("비밀번호 불일치 또는 파일명/헤더 위변조(HMAC 실패)"
                              if parsed.get("wrong_password_or_tampered") else "암호 잠김 (복호화 비밀번호 입력 필요)")
                findings.append(f"[확정/CRITICAL] 오프셋 0x{eof_pos:X} 암호화 패킷({parsed['filename']}, {ver}) [{status_msg}]")
                emit(f"  [!] 경보: 0x{eof_pos:X} 암호화 EOF 패킷 발견 ({ver}) | 파일명: {parsed['filename']} -> {status_msg}")
                _add(result, "EOF 암호화 패킷", f"암호 잠김 ({ver})", f"0x{eof_pos:X}", file_bytes[eof_pos:eof_pos + parsed["total_packet_bytes"]], f"파일명: {parsed['filename']} ({status_msg})", parsed["filename"])
            else:
                integ_str = "무결성 검증 통과" if parsed["integrity_ok"] else "경고: 파일명/헤더 또는 본문 위변조됨!"
                sev = "CRITICAL" if parsed["integrity_ok"] else "TAMPERED"
                findings.append(f"[확정/{sev}] 오프셋 0x{eof_pos:X} 은닉 패킷({parsed['filename']}, {ver}) 복원 [{integ_str}]")
                emit(f"  [!] 경보: 0x{eof_pos:X} EOF 은닉 패킷 복원 ({ver}) | 파일명: {parsed['filename']} ({parsed['original_size']:,} B) | {integ_str}")
                _add(result, "EOF 은닉 패킷", f"은닉 파일 ({ver})", f"0x{eof_pos:X}", parsed["payload"], f"파일명: {parsed['filename']} ({integ_str})", parsed["filename"])
        else:
            emit(f"  [*] 참고: 오프셋 0x{eof_pos:X} 에 시그니처 문자열이 있으나 유효한 패킷 구조가 아닙니다 (더미/오탐 건너뜀).")

    if natural_eof < result.filesize:
        trailing_len = result.filesize - natural_eof
        findings.append(f"[확정/WARNING] {carrier_fmt} 정상 종료 지점(0x{natural_eof:X}) 이후 {trailing_len:,} bytes 후미 데이터 존재")
        emit(f"  [!] 주의: 정상 종료 지점 뒤에 {trailing_len:,} bytes의 잉여 데이터가 결합되어 있습니다!")
        if valid_eof_packets == 0:
            _add(result, "EOF 후미 결합", "Trailing Stream", f"0x{natural_eof:X}", file_bytes[natural_eof:], f"{carrier_fmt} 종료 마커 뒤 은닉 데이터", "trailing_extracted.bin")
    else:
        emit("  [+] 정상: 파일 종료 마커 이후에 덧붙여진 잉여 바이트가 없습니다.")

    # [2] 미디어 카빙
    emit("\n[2] 이종 미디어 카빙 스캔 (Image / Video / Audio / Archive inside File)")
    carved_media = carve_embedded_media(file_bytes, carrier_fmt, natural_eof)
    if carved_media:
        for cm in carved_media:
            findings.append(f"[확정/HIGH] 오프셋 0x{cm['offset']:X} 은닉 미디어 [{cm['label']}] 발견 ({cm['size']:,} bytes)")
            emit(f"  [!] 은닉 미디어 탐지: {cm['label']} (0x{cm['offset']:X}, {cm['size']:,} bytes)")
            _add(result, "미디어 카빙", cm["label"], f"0x{cm['offset']:X}", cm["data"], cm["note"], f"carved_0x{cm['offset']:X}{cm['ext']}")
    else:
        emit("  [+] 정상: 내부에 숨겨진 추가 이미지, 동영상, 오디오, 압축 파일이 없습니다.")

    # [3] LSB
    emit("\n[3] 픽셀 LSB (PixelCode) 및 WAV 샘플 단위 LSB 스테가노그래피 분석")
    # 분기는 파일명 확장자가 아니라 '내용(매직바이트)'으로 결정 — 스테가 이미지를 .unknown 등 비이미지
    # 확장자로 위장해도 픽셀/오디오/비디오 스테가분석이 누락되지 않게 한다(실제 멀웨어 회피 갭 차단).
    ext = _effective_ext(file_bytes, target_path)
    if PIL_AVAILABLE and ext in (".png", ".bmp", ".jpg", ".jpeg", ".webp"):
        try:
            img = Image.open(target_path).convert("RGB")
            pixels = img.tobytes()
            # JPEG은 손실압축 → 디코딩한 픽셀의 LSB는 저장 비트가 아니므로 공간 LSB 패킷 탐지는 의미 없음(스킵)
            if ext not in (".jpg", ".jpeg"):
                inspect_lsb_carrier(pixels, "픽셀 LSB", password, result, findings, sampwidth=1)
            _image_steganalysis(img, file_bytes, ext, findings, emit)
        except Exception as e:
            emit(f"  [-] 이미지 픽셀 분석 예외: {e}")
    elif ext == ".wav":
        try:
            with wave.open(target_path, "rb") as wf:
                sampwidth = wf.getsampwidth()
                nchannels = wf.getnchannels()
                raw_audio = wf.readframes(wf.getnframes())
            _audio_steganalysis(raw_audio, sampwidth, nchannels, findings, emit)
            found = inspect_lsb_carrier(raw_audio, f"WAV 샘플 LSB ({sampwidth * 8}-bit)", password, result, findings, sampwidth=sampwidth)
            if not found and sampwidth > 1:
                inspect_lsb_carrier(raw_audio, "WAV 바이트 LSB (Legacy v4)", password, result, findings, sampwidth=1, quiet_if_clean=True)
        except Exception as e:
            emit(f"  [-] WAV 오디오 LSB 분석 예외: {e}")
    elif ext in (".mp4", ".mkv", ".avi", ".mov", ".webm", ".m4v", ".nut"):
        _video_frames(target_path, findings, emit)
    else:
        emit("  [-] LSB 스테가노그래피 대상(이미지 또는 WAV 오디오)이 아닙니다.")

    # [4] 메타데이터/청크
    emit("\n[4] 메타데이터 및 비표준 청크(PNG zTXt/iTXt / JPEG EXIF / PDF 액션 객체 / ID3) 분석")
    meta_report, meta_threats, meta_payloads = inspect_metadata_and_chunks(file_bytes, carrier_fmt)
    result.meta_report = meta_report
    if meta_threats:
        for mt in meta_threats:
            findings.append(f"[구조/HIGH] 메타데이터/객체 위험 요소 탐지: {mt}")
            emit(f"  [!] 경보: {mt}")
    else:
        emit("  [+] 정상: 메타데이터 및 문서 객체 내에서 비정상 실행 구조가 발견되지 않았습니다.")

    # [4-E] 파일 메타데이터(PDF/Office/MP3/MP4 등) — 작성자/소프트웨어/일시/제목 (이미지는 [3]에서 처리)
    try:
        fm_rows, fm_alerts = extract_file_metadata(file_bytes)
        if fm_rows:
            emit("\n[4-E] 파일 메타데이터 (작성자 / 소프트웨어 / 일시 / 제목)")
            for k, v in fm_rows:
                emit(f"      {k}: {v}")
            for a in fm_alerts:
                findings.append(f"[메타데이터/MEDIUM] {a}")
                emit(f"  [!] 메타데이터 경보: {a}")
    except Exception as e:
        emit(f"  [-] 파일 메타데이터 추출 예외: {e}")

    # [4-B] 구조 내부 코드 추출 → 항목으로 승격 (PDF 액션 + PNG/JPEG/MP3 메타데이터 코드)
    for sp in extract_structural_payloads(file_bytes, carrier_fmt) + meta_payloads:
        _add(result, sp["category"], sp["fmt"], sp["offset"], sp["data"], sp["detail"], sp["name"], sp.get("decoded"))
        findings.append(f"[구조/HIGH] {carrier_fmt} 구조 내부 은닉 코드 추출: {sp['fmt']} → {sp['name']}")
        emit(f"  [+] 구조 내부 코드 추출 → 뷰어 항목 추가: {sp['name']} ({sp['offset']})")

    # [4-C] 문서형(HWP/Office/OOXML) 내부 구조 분석 — OLE 스트림·ZIP 파트·VBA 매크로
    ext = os.path.splitext(target_path)[1].lower()
    doc_report, doc_threats, doc_payloads = docscan.analyze_document(file_bytes, ext)
    if doc_report:
        emit("\n[4-C] 문서 구조 분석 (HWP / Office / OOXML / VBA 매크로)")
        result.meta_report += "\n\n" + doc_report
        for dt in doc_threats:
            findings.append(f"[문서/HIGH] 문서 내부 위협: {dt}")
            emit(f"  [!] 경보: {dt}")
        for sp in doc_payloads:
            _add(result, sp["category"], sp["fmt"], sp["offset"], sp["data"], sp["detail"], sp["name"], sp.get("decoded"))
            emit(f"  [+] 문서 내부 객체/코드 추출 → 뷰어 항목 추가: {sp['name']} ({sp['offset']})")
        if not doc_threats and not doc_payloads:
            emit("  [+] 정상: 문서 내부에서 특이 위협이 발견되지 않았습니다.")

    # [4-D] 컨테이너 틈새 검사 (PNG IDAT / MP4 박스·미참조 mdat)
    c_lines, c_threats, c_payloads = container.inspect(file_bytes)
    if c_lines or c_threats:
        emit("\n[4-D] 컨테이너 내부 틈새 검사 (PNG IDAT 압축 스트림 / MP4 박스 구조)")
        for ln in c_lines[:60]:
            emit("  " + ln)
        result.meta_report += "\n\n[컨테이너 구조]\n" + "\n".join(c_lines)
        for grade, msg in c_threats:
            findings.append(f"[컨테이너/{grade}] {msg}")
            emit(f"  [!] {msg}")
        for sp in c_payloads:
            _add(result, sp["category"], sp["fmt"], sp["offset"], sp["data"], sp["detail"], sp["name"])
            emit(f"  [+] 컨테이너 은닉 데이터 추출 → 뷰어 항목 추가: {sp['name']}")
        if not c_threats:
            emit("  [+] 정상: 컨테이너 내부 틈새에서 은닉 흔적이 없습니다.")

    # [5] 코드/YARA 패턴
    yara_mode_str = "정식 yara-python 엔진" if YARA_ENGINE_AVAILABLE else "내장 정규식 시그니처(Regex Heuristic)"
    emit(f"\n[5] 코드/스크립트 패턴 & 난독화 디코딩 & 위협 룰 매칭 ({yara_mode_str})")
    detected_any_code = False
    for item in result.carved:
        if not item.data or "암호 잠김" in item.format:
            continue
        p_media = analysis.identify_buffer_media_type(item.data)
        p_langs, p_heur, p_decoded = scan_all_languages_and_deobfuscate(item.data)
        yara_hits = run_yara_or_regex_rules(item.data, p_decoded)
        if p_decoded and not item.decoded_text:
            item.decoded_text = p_decoded
        if yara_hits:
            yara_str = ", ".join(yara_hits)
            item.detail += f" | 패턴매칭: {yara_str}"
            findings.append(f"[패턴주의/HIGH] 추출 항목 #{item.id} 의심 명령 패턴 매칭 [{yara_str}]")
        if p_media:
            item.format = p_media
        elif p_langs:
            detected_any_code = True
            item.format = f"코드 패턴: {', '.join(p_langs[:2])}"
            findings.append(f"[코드식별/MEDIUM] 추출 항목 #{item.id} ({item.name}) 코드 시그니처 매칭 [{', '.join(p_langs)}]")
            emit(f"  [!] 추출 항목 #{item.id} 코드/디코딩 시그니처: {', '.join(p_langs)}")
        elif p_heur["is_code"]:
            detected_any_code = True
            item.format = "텍스트/코드 추정 (Heuristic)"
            emit(f"  [*] 추출 항목 #{item.id} 범용 코드 구문 휴리스틱 양성 (구문 밀도: {p_heur['density']:.1%})")

    if not result.carved:
        c_langs, _, c_decoded = scan_all_languages_and_deobfuscate(file_bytes)
        yara_hits = run_yara_or_regex_rules(file_bytes, c_decoded)
        if c_langs or yara_hits:
            detected_any_code = True
            if c_langs:
                findings.append(f"[참고/LOW] 컨테이너 본문 내 코드/문서 키워드 정규식 매칭 ({', '.join(c_langs)}) - 정상 텍스트 여부 확인 필요")
                emit(f"  [*] 참고(정규식 매칭): 컨테이너 내부에서 코드 관련 키워드가 발견되었습니다 ({', '.join(c_langs)}).")
            if yara_hits:
                findings.append(f"[패턴주의/MEDIUM] 컨테이너 본문 내 명령어 패턴 매칭 ({', '.join(yara_hits)})")
                emit(f"  [!] 주의(패턴 매칭): {', '.join(yara_hits)}")
        else:
            # 코드/패턴이 전혀 안 잡혔을 때만 난독 블롭 휴리스틱 (미니파이 코드는 위에서 걸러짐)
            blob_hit, blob_desc = obfuscated_blob_score(file_bytes)
            if blob_hit:
                detected_any_code = True
                findings.append(f"[난독화/MEDIUM] {blob_desc}")
                emit(f"  [!] {blob_desc}")

    if not detected_any_code:
        emit("  [+] 정상: 알려진 코드 시그니처 및 난독화 패턴이 발견되지 않았습니다.")

    # [6] 재귀 추출 — 카빙된 항목 '내부'에 또 숨은 컨테이너/문서/코드 재검사(중첩 은닉 대응)
    emit("\n[6] 재귀 추출 (카빙 항목 내부 재스캔, 최대 2단계)")
    _recursive_extract(result, findings, emit)

    # [7] 텍스트 스테가노그래피 (제로폭 문자 / 줄끝 공백 / 동형 문자)
    emit("\n[7] 텍스트 스테가노그래피 (제로폭 문자 / SNOW 화이트스페이스 / 동형 문자)")
    text_hits = 0
    body_text = steganalysis.bytes_as_text(file_bytes)
    sources = [("파일 본문", body_text)]
    sources += [(f"추출 항목 #{it.id}", it.decoded_text) for it in result.carved if it.decoded_text]
    for label, text in sources:
        for grade, msg in steganalysis.text_stego_check(text):
            text_hits += 1
            findings.append(f"[텍스트스테그/{grade}] {label}: {msg}")
            emit(f"  [!] {label}: {msg}")
    if not text_hits:
        emit("  [+] 정상: 텍스트 은닉 흔적이 없습니다.")

    # [8] IOC(침해지표) 추출
    emit("\n[8] IOC 추출 (URL / IP / 도메인 / 이메일 / 해시)")
    texts = ["\n".join(extract_strings(file_bytes, min_len=6, max_count=20000)), body_text]
    for it in result.carved:
        texts.append(it.decoded_text)
        if it.data and "암호 잠김" not in it.format:
            texts.append("\n".join(extract_strings(it.data, min_len=6, max_count=5000)))
    result.iocs = ioc.extract_iocs(texts, exclude_hashes=(result.md5, result.sha1, result.sha256))
    if result.iocs:
        summary = ", ".join(f"{k} {len(v)}" for k, v in result.iocs.items())
        emit(f"  [*] IOC: {summary}")
        result.meta_report += "\n\n[IOC 침해지표]\n" + ioc.format_iocs(result.iocs)
        for line in ioc.format_iocs(result.iocs).splitlines()[:40]:
            emit("    " + line)
        if any(k in result.iocs for k in ("url", "ipv4", "email")):
            findings.append(f"[IOC/LOW] 네트워크 지표 발견 ({summary}) - 위협 인텔리전스 대조 권장")
    else:
        emit("  [+] IOC가 발견되지 않았습니다.")

    emit("\n" + "=" * 72)
    if findings:
        emit(f" [최종 판정] 총 {len(findings)}건의 분석 항목이 보고되었습니다:")
        for idx, f_msg in enumerate(findings, 1):
            emit(f"  {idx}. {f_msg}")
    else:
        emit(" [최종 판정] 안전 (은닉된 패킷, 후미 결합 미디어, 비정상 구조가 발견되지 않았습니다.)")
    emit("=" * 72)

    return result


def bit_plane_lut_image(path, channel_idx, bit_idx):
    """
    이미지의 특정 채널·비트 평면을 흑백(L) PIL 이미지로 반환한다.
    channel_idx: 0=R, 1=G, 2=B, 3=Grayscale / bit_idx: 0(LSB)~7(MSB)
    PIL 미설치 또는 비이미지면 None.
    """
    if not PIL_AVAILABLE:
        return None
    img = Image.open(path).convert("RGB")
    r, g, b = img.split()
    target_ch = [r, g, b, img.convert("L")][channel_idx]
    mask = 1 << bit_idx
    lut = [255 if (i & mask) else 0 for i in range(256)]
    return target_ch.point(lut, mode="L")


def cdr_sanitize(file_bytes, source_path, natural_eof):
    """
    CDR 무해화: 숨겨진 데이터를 제거한 안전 사본 바이트를 반환한다. (out_bytes, info_msg)
    - 이미지: 알파 보존 + RGB 하위 2비트 클리어 + 메타데이터/EOF 후미 제거(재인코딩)
    - WAV: 샘플 최하위 바이트 LSB 초기화
    - 그 외(PDF/동영상 등): 정상 종료지점 이후 후미 스트림 절단
    """
    ext = os.path.splitext(source_path)[1].lower()

    if PIL_AVAILABLE and ext in (".png", ".bmp", ".jpg", ".jpeg", ".webp"):
        orig_img = Image.open(io.BytesIO(file_bytes))
        has_alpha = orig_img.mode in ("RGBA", "LA") or ("transparency" in orig_img.info)
        mode = "RGBA" if has_alpha else "RGB"
        img = orig_img.convert(mode)
        if mode == "RGBA":
            r, g, b, a = img.split()
            raw_rgb = bytearray(Image.merge("RGB", (r, g, b)).tobytes())
            for i in range(len(raw_rgb)):
                raw_rgb[i] &= 0xFC
            clean_rgb = Image.frombytes("RGB", img.size, bytes(raw_rgb))
            cr, cg, cb = clean_rgb.split()
            clean_img = Image.merge("RGBA", (cr, cg, cb, a))
        else:
            raw_rgb = bytearray(img.tobytes())
            for i in range(len(raw_rgb)):
                raw_rgb[i] &= 0xFC
            clean_img = Image.frombytes("RGB", img.size, bytes(raw_rgb))
        fmt_map = {".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG", ".bmp": "BMP", ".webp": "WEBP"}
        buf = io.BytesIO()
        clean_img.save(buf, format=fmt_map.get(ext, "PNG"))
        return buf.getvalue(), (f"이미지 재인코딩 완료 ({mode}) · RGB 하위 2비트 클리어 · "
                                "EXIF/tEXt/zTXt 메타데이터 및 EOF 후미 제거")

    if ext == ".wav":
        with wave.open(io.BytesIO(file_bytes), "rb") as wf:
            params = wf.getparams()
            sampwidth = wf.getsampwidth()
            frames = bytearray(wf.readframes(wf.getnframes()))
        for pos in range(0, len(frames), sampwidth):
            frames[pos] &= 0xFE
        buf = io.BytesIO()
        with wave.open(buf, "wb") as wf_out:
            wf_out.setparams(params)
            wf_out.writeframes(bytes(frames))
        return buf.getvalue(), f"WAV 샘플 단위({sampwidth * 8}-bit) LSB 초기화 및 EOF 후미 제거 완료"

    clean_bytes = file_bytes[:natural_eof]
    note = f"정상 종료 오프셋(0x{natural_eof:X}) 이후 결합 데이터를 절단했습니다."
    if clean_bytes.startswith(b"%PDF"):
        note += " (PDF 내부 객체 완전 재구성은 전용 렌더러 기반 변환을 권장)"
    return clean_bytes, note


def build_report_dict(result):
    """ScanResult를 직렬화 가능한 dict로 변환 (JSON 리포트 및 HTML 생성 공용)."""
    return {
        "filename": result.filename,
        "filepath": result.filepath,
        "filesize": result.filesize,
        "carrier_format": result.carrier_fmt,
        "natural_eof": result.natural_eof,
        "overall_entropy": round(result.overall_entropy, 4),
        "hashes": {"md5": result.md5, "sha1": result.sha1, "sha256": result.sha256},
        "findings": list(result.findings),
        "carved_items": [
            {"id": it.id, "category": it.category, "format": it.format,
             "offset": it.offset, "size": it.size, "detail": it.detail, "name": it.name}
            for it in result.carved
        ],
        "meta_report": result.meta_report,
        "iocs": getattr(result, "iocs", {}),
    }


def build_report_json(result):
    return json.dumps(build_report_dict(result), ensure_ascii=False, indent=2)


def build_report_html(result):
    import html as _html
    d = build_report_dict(result)
    rows = "".join(
        f"<tr><td>{c['id']}</td><td>{_html.escape(c['category'])}</td>"
        f"<td>{_html.escape(c['format'])}</td><td>{_html.escape(c['offset'])}</td>"
        f"<td>{c['size']:,}</td><td>{_html.escape(c['detail'])}</td></tr>"
        for c in d["carved_items"]
    ) or "<tr><td colspan='6'>탐지 항목 없음</td></tr>"
    finds = "".join(f"<li>{_html.escape(f)}</li>" for f in d["findings"]) or "<li>특이사항 없음</li>"
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>포렌식 리포트 - {_html.escape(d['filename'])}</title>
<style>
body{{font-family:'Malgun Gothic',sans-serif;background:#1e1e2e;color:#cdd6f4;margin:0;padding:28px}}
h1{{color:#89b4fa}} h2{{color:#b4befe;border-bottom:1px solid #313244;padding-bottom:6px}}
table{{border-collapse:collapse;width:100%;margin:8px 0}}
th,td{{border:1px solid #313244;padding:7px 9px;text-align:left;font-size:13px}}
th{{background:#313244;color:#89b4fa}} code{{color:#a6e3a1}}
.meta{{background:#11111b;padding:12px;border-radius:8px;font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap}}
</style></head><body>
<h1>Stego &amp; Forensic Security Studio — 분석 리포트</h1>
<h2>파일 정보</h2>
<table>
<tr><th>파일명</th><td>{_html.escape(d['filename'])}</td></tr>
<tr><th>크기</th><td>{d['filesize']:,} bytes ({_html.escape(d['carrier_format'])})</td></tr>
<tr><th>정상 종료지점</th><td>0x{d['natural_eof']:X}</td></tr>
<tr><th>전체 엔트로피</th><td>{d['overall_entropy']} / 8.0</td></tr>
<tr><th>MD5</th><td><code>{d['hashes']['md5']}</code></td></tr>
<tr><th>SHA-1</th><td><code>{d['hashes']['sha1']}</code></td></tr>
<tr><th>SHA-256</th><td><code>{d['hashes']['sha256']}</code></td></tr>
</table>
<h2>종합 판정 ({len(d['findings'])}건)</h2><ul>{finds}</ul>
<h2>탐지 항목 ({len(d['carved_items'])}개)</h2>
<table><tr><th>#</th><th>기법</th><th>포맷/언어</th><th>오프셋</th><th>크기(B)</th><th>세부</th></tr>{rows}</table>
<h2>IOC (침해지표)</h2>
<div class="meta">{_html.escape(ioc.format_iocs(d['iocs']))}</div>
<h2>메타데이터 / 구조 분석</h2>
<div class="meta">{_html.escape(d['meta_report'])}</div>
</body></html>"""


def _verdict(result):
    crit = [f for f in result.findings if any(k in f for k in ("CRITICAL", "HIGH", "WARNING", "TAMPERED"))]
    return ("의심" if crit else "참고" if result.findings else "정상"), (crit or result.findings or ["특이사항 없음"])[0]


def build_batch_csv(results):
    """일괄 스캔 결과 목록 → CSV 문자열 (Excel 한글 호환 UTF-8 BOM 포함)."""
    import csv
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["파일", "경로", "판정", "포맷", "크기", "SHA-256", "판정건수", "추출항목", "IOC", "대표 탐지"])
    for r in results:
        v, top = _verdict(r)
        iocs = "; ".join(f"{k}:{len(x)}" for k, x in getattr(r, "iocs", {}).items())
        w.writerow([r.filename, r.filepath, v, r.carrier_fmt, r.filesize, r.sha256,
                    len(r.findings), len(r.carved), iocs, top])
    return "\ufeff" + buf.getvalue()


def build_batch_html(results):
    """일괄 스캔 결과 목록 → 요약 HTML."""
    import html as _h
    rows = []
    for i, r in enumerate(results, 1):
        v, top = _verdict(r)
        color = {"의심": "#f38ba8", "참고": "#f9e2af"}.get(v, "#a6e3a1")
        rows.append(f"<tr><td>{i}</td><td style='color:{color}'>{v}</td><td>{_h.escape(r.filename)}</td>"
                    f"<td>{_h.escape(r.carrier_fmt)}</td><td>{r.filesize:,}</td><td>{len(r.findings)}</td>"
                    f"<td>{_h.escape(top)}</td></tr>")
    n_sus = sum(1 for r in results if _verdict(r)[0] == "의심")
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>일괄 스캔 리포트</title>
<style>body{{font-family:'Malgun Gothic',sans-serif;background:#1e1e2e;color:#cdd6f4;padding:28px}}
h1{{color:#89b4fa}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #313244;padding:6px 8px;font-size:13px;text-align:left}}
th{{background:#313244;color:#89b4fa}}</style></head><body>
<h1>일괄 스캔 리포트</h1><p>총 {len(results)}개 파일 · 의심 {n_sus}개</p>
<table><tr><th>#</th><th>판정</th><th>파일</th><th>포맷</th><th>크기(B)</th><th>판정건수</th><th>대표 탐지</th></tr>
{''.join(rows)}</table></body></html>"""


def diff_files(path_a, path_b, max_ranges=50):
    """
    원본(a)과 의심본(b)을 비교. 바이트 차이 구간 + (둘 다 이미지·같은 크기면) 픽셀/LSB 차이 통계.
    반환: 사람이 읽는 리포트 문자열.
    """
    with open(path_a, "rb") as f:
        a = f.read()
    with open(path_b, "rb") as f:
        b = f.read()
    out = [f"A: {path_a} ({len(a):,} B)", f"B: {path_b} ({len(b):,} B)"]
    if a == b:
        return "\n".join(out + ["[=] 두 파일이 완전히 동일합니다."])
    ranges, start, diff_bytes = [], None, 0
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            diff_bytes += 1
            if start is None:
                start = i
        elif start is not None:
            ranges.append((start, i))
            start = None
    if start is not None:
        ranges.append((start, n))
    out.append(f"[*] 공통 길이 {n:,} B 중 {diff_bytes:,} B 다름 ({len(ranges):,}개 구간)")
    for s0, e0 in ranges[:max_ranges]:
        out.append(f"    0x{s0:X} ~ 0x{e0:X} ({e0 - s0:,} B)")
    if len(ranges) > max_ranges:
        out.append(f"    … 외 {len(ranges) - max_ranges}개 구간")
    if len(a) != len(b):
        longer, tail = ("B", b[n:]) if len(b) > len(a) else ("A", a[n:])
        if diff_bytes == 0:     # 앞부분이 완전히 같고 뒤에만 붙은 경우 = 후미 결합
            out.append(f"[!] {longer} 끝에 {len(tail):,} B 추가 데이터 (엔트로피 {analysis.calc_entropy(tail):.2f}) — 후미 결합 은닉 의심")
        else:
            out.append(f"[*] 크기 차이 {len(tail):,} B (재인코딩/재압축 가능성 — 아래 픽셀 비교 참고)")
    if PIL_AVAILABLE:
        try:
            ia, ib = Image.open(path_a).convert("RGB"), Image.open(path_b).convert("RGB")
            if ia.size == ib.size:
                changed = lsb_only = 0
                for x, y in zip(ia.tobytes(), ib.tobytes()):
                    if x != y:
                        changed += 1
                        if x ^ y == 1:
                            lsb_only += 1
                out.append(f"[*] 픽셀 비교 ({ia.size[0]}x{ia.size[1]}): 채널값 {changed:,}개 변경, 그중 LSB만 바뀐 값 {lsb_only:,}개")
                if changed and lsb_only / changed > 0.9:
                    out.append("[!] 변경이 거의 LSB에만 있음 — LSB 스테가노그래피 은닉 강하게 의심")
            else:
                out.append(f"[*] 이미지 크기 다름: {ia.size} vs {ib.size}")
        except Exception:
            pass
    return "\n".join(out)


def _recursive_extract(result, findings, emit, max_depth=2, max_added=50):
    """
    이미 카빙된 항목의 data 안을 다시 스캔해 중첩 은닉(예: PNG 안의 ZIP, ZIP 안의 docx)을
    항목으로 추가한다. 무한증식 방지를 위해 깊이·개수·크기 상한과 중복 제거를 둔다.
    """
    def key_of(data, label):
        return (label, len(data), bytes(data[:16]))

    seen = set()
    for it in result.carved:
        if it.data:
            seen.add(key_of(it.data, it.format))

    worklist = [(it, 1) for it in list(result.carved) if it.data and len(it.data) > 64]
    added = 0
    while worklist and added < max_added:
        item, depth = worklist.pop(0)
        if depth > max_depth:
            continue
        sub = item.data

        # (a) 내부 미디어/아카이브 카빙 (자기 자신 전체는 제외)
        for cm in carve_embedded_media(sub, "RECURSE", 0):
            if cm["offset"] == 0 and cm["size"] >= len(sub):
                continue
            k = key_of(cm["data"], cm["label"])
            if k in seen or len(cm["data"]) < 32:
                continue
            seen.add(k)
            newit = _add(result, "재귀 카빙", cm["label"], f"{item.offset}+0x{cm['offset']:X}",
                         cm["data"], f"{item.name} 내부: {cm['note']}",
                         f"nested_{cm['offset']:X}{cm['ext']}")
            findings.append(f"[재귀/HIGH] {item.name} 내부에서 {cm['label']} 추출 ({cm['size']:,} B)")
            emit(f"  [+] 재귀 추출: {item.name} → {cm['label']} ({newit.size:,} B)")
            added += 1
            if newit.size > 64 and depth < max_depth:
                worklist.append((newit, depth + 1))
            if added >= max_added:
                break

        # (b) 내부가 문서(HWP/Office/OOXML)이면 문서 분석
        try:
            _drep, dthreats, dpayloads = docscan.analyze_document(sub, "")
        except Exception:
            dthreats, dpayloads = [], []
        for sp in dpayloads:
            k = key_of(sp["data"], sp["fmt"])
            if k in seen:
                continue
            seen.add(k)
            _add(result, "재귀 문서코드", sp["fmt"], f"{item.offset}:{sp['offset']}",
                 sp["data"], f"{item.name} 내부 문서: {sp['detail']}", sp["name"], sp.get("decoded"))
            added += 1
        for dt in dthreats:
            findings.append(f"[재귀/HIGH] {item.name} 내부 문서 위협: {dt}")

    if added == 0:
        emit("  [+] 정상: 카빙 항목 내부에서 추가 중첩 은닉이 발견되지 않았습니다.")
    else:
        emit(f"  [*] 재귀 추출로 {added}개 항목을 추가했습니다.")


def query_virustotal(target_bytes, api_key, timeout=10):
    """VirusTotal 해시 조회 (해시만 전송, 파일 본문은 보내지 않음). (msg, is_error) 반환."""
    sha256_hash = hashlib.sha256(target_bytes).hexdigest()
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            res_json = json.loads(resp.read().decode("utf-8"))
            stats = res_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            und = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)
            msg = (f"[VirusTotal 조회 결과]\n• SHA-256: {sha256_hash}\n\n"
                   f"• 악성(Malicious) 판정 : {mal}개 엔진\n"
                   f"• 의심(Suspicious) 판정 : {susp}개 엔진\n"
                   f"• 정상/미탐지(Clean) : {harmless + und}개 엔진")
            return msg, False
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return f"해당 해시({sha256_hash[:16]}...)는 VirusTotal DB에 미등록된 파일입니다.", True
        return f"VirusTotal HTTP {e.code} 오류가 발생했습니다.", True
    except Exception as e:
        return f"네트워크 오류: {e}", True


import urllib.parse  # noqa: E402  (scan_all_languages에서 사용)
