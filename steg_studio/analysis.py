"""
포렌식 분석 보조 유틸리티 (GUI 비의존 순수 함수).

- calc_entropy()             : 바이트 블록의 섀넌 엔트로피(0~8 bits) 계산
- identify_buffer_media_type(): 매직 바이트로 버퍼의 미디어 포맷 식별
- format_hex_dump()          : 바이트를 사람이 읽는 Hex 덤프 문자열로 변환
"""

import math


def calc_entropy(data: bytes) -> float:
    """바이트 데이터의 섀넌 엔트로피(0.0 ~ 8.0 bits)를 계산합니다. 값이 높을수록 암호화/압축 가능성이 큽니다."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def identify_buffer_media_type(buf: bytes):
    """버퍼 선두의 매직 바이트로 미디어/아카이브 포맷을 식별합니다. 미상이면 None을 반환합니다."""
    if buf.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG 이미지"
    if buf.startswith(b"\xff\xd8\xff"):
        return "JPEG 이미지"
    if buf.startswith((b"GIF87a", b"GIF89a")):
        return "GIF 이미지"
    if buf.startswith(b"BM") and len(buf) > 14:
        return "BMP 이미지"
    if buf.startswith(b"RIFF") and len(buf) >= 12:
        sub = buf[8:12]
        if sub == b"WEBP":
            return "WEBP 이미지"
        if sub == b"AVI ":
            return "AVI 동영상"
        if sub == b"WAVE":
            return "WAV 오디오"
    if len(buf) >= 12 and buf[4:8] == b"ftyp":
        return "MP4/MOV 동영상"
    if buf.startswith(b"\x1a\x45\xdf\xa3"):
        return "MKV/WebM 동영상"
    if buf.startswith(b"%PDF"):
        return "PDF 문서"
    if buf.startswith(b"PK\x03\x04"):
        return "ZIP 아카이브"
    return None


def is_text_buffer(data: bytes, filename: str = "") -> bool:
    """텍스트 뷰어에서 깨진 바이너리가 문자처럼 표시되지 않게 판별한다."""
    import os

    sample = data[:8192]
    if os.path.splitext(filename)[1].lower() == ".pyc" or b"\x00" in sample:
        return False
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    controls = sum(
        1 for char in text
        if ord(char) < 32 and char not in "\t\n\r\f\b"
    )
    return controls <= max(1, len(text) // 100)


def entropy_blocks(data: bytes, max_blocks: int = 100, min_blocks: int = 16):
    """파일을 균등 블록으로 나눠 블록별 엔트로피 리스트를 반환한다 (엔트로피 그래프용)."""
    if not data:
        return []
    num_blocks = min(max_blocks, max(min_blocks, len(data) // 1024))
    block_size = max(1, len(data) // num_blocks)
    out = []
    for i in range(num_blocks):
        chunk = data[i * block_size:(i + 1) * block_size]
        if not chunk:
            break
        out.append(calc_entropy(chunk))
    return out


def format_hex_dump(data: bytes) -> str:
    """바이트 데이터를 오프셋 + Hex + ASCII 3단 Hex 덤프 문자열로 변환합니다."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:08X}  {hex_part:<47}  |{ascii_part}|")
    return "\n".join(lines)
