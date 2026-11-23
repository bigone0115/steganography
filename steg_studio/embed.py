"""
은닉(스테가노그래피) 생성 로직 (UI 비의존).

각 함수는 결과 바이트와 권장 확장자를 반환한다. 파일 저장/대화상자는 GUI가 담당한다.
"""

import io
import os
import wave

from . import crypto
from .constants import LSB_MAGIC, EOF_MAGIC

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


def embed_pixelcode_lsb(carrier_path, payload_path, payload_bytes, password=""):
    """이미지 RGB 픽셀의 최하위 비트(LSB)에 패킷을 분산 삽입 → 무손실 PNG 바이트 반환."""
    if not PIL_AVAILABLE:
        raise RuntimeError("Pillow 라이브러리가 필요합니다 (pip install pillow).")
    orig_img = Image.open(carrier_path)
    target_mode = "RGBA" if orig_img.mode in ("RGBA", "LA") or ("transparency" in orig_img.info) else "RGB"
    img = orig_img.convert(target_mode)

    packet = crypto.build_packet(LSB_MAGIC, payload_path, payload_bytes, password)
    total_bits = len(packet) * 8

    if target_mode == "RGBA":
        r, g, b, a = img.split()
        rgb_img = Image.merge("RGB", (r, g, b))
        rgb_bytes = bytearray(rgb_img.tobytes())
    else:
        rgb_bytes = bytearray(img.tobytes())

    if total_bits > len(rgb_bytes):
        raise ValueError(f"이미지 해상도 부족: 필요 비트 {total_bits:,} / 가용 RGB 바이트 {len(rgb_bytes):,}")

    bit_idx = 0
    for byte_val in packet:
        for shift in range(7, -1, -1):
            rgb_bytes[bit_idx] = (rgb_bytes[bit_idx] & 0xFE) | ((byte_val >> shift) & 1)
            bit_idx += 1

    modified_rgb = Image.frombytes("RGB", img.size, bytes(rgb_bytes))
    if target_mode == "RGBA":
        mr, mg, mb = modified_rgb.split()
        out_img = Image.merge("RGBA", (mr, mg, mb, a))
    else:
        out_img = modified_rgb

    buf = io.BytesIO()
    out_img.save(buf, format="PNG")
    return buf.getvalue(), ".png", f"PixelCode 은닉 완료 (컬러모드 {target_mode}, 패킷 {len(packet):,} bytes)"


def embed_audio_wav_lsb(carrier_path, payload_path, payload_bytes, password=""):
    """WAV 각 PCM 샘플의 최하위 바이트 Bit0에만 삽입 → WAV 바이트 반환."""
    if not carrier_path.lower().endswith(".wav"):
        raise ValueError("Audio LSB 모드는 비압축 WAV(.wav)만 지원합니다.")
    with wave.open(carrier_path, "rb") as wf:
        params = wf.getparams()
        sampwidth = wf.getsampwidth()
        nchannels = wf.getnchannels()
        frames = bytearray(wf.readframes(wf.getnframes()))

    total_samples = len(frames) // sampwidth
    packet = crypto.build_packet(LSB_MAGIC, payload_path, payload_bytes, password)
    total_bits = len(packet) * 8
    if total_bits > total_samples:
        raise ValueError(f"WAV 샘플 수 부족: 필요 {total_bits:,} / 가용 {total_samples:,} ({sampwidth * 8}-bit)")

    sample_idx = 0
    for byte_val in packet:
        for shift in range(7, -1, -1):
            byte_pos = sample_idx * sampwidth
            frames[byte_pos] = (frames[byte_pos] & 0xFE) | ((byte_val >> shift) & 1)
            sample_idx += 1

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf_out:
        wf_out.setparams(params)
        wf_out.writeframes(bytes(frames))
    return buf.getvalue(), ".wav", f"WAV Audio LSB 은닉 완료 ({sampwidth * 8}-bit PCM, {nchannels}ch)"


def embed_eof_packet(carrier_path, payload_path, payload_bytes, password=""):
    """원본 미디어 뒤에 EOF_MAGIC + 압축/암호화 패킷을 결합 → 결합 바이트 반환."""
    with open(carrier_path, "rb") as f:
        carrier_bytes = f.read()
    packet = crypto.build_packet(EOF_MAGIC, payload_path, payload_bytes, password)
    ext = os.path.splitext(carrier_path)[1] or ".bin"
    return carrier_bytes + packet, ext, f"EOF 패킷 결합 완료 (패킷 {len(packet):,} bytes)"


def embed_raw_concat(carrier_path, payload_bytes):
    """원본 미디어 뒤에 숨길 파일 원본을 그대로 결합(Polyglot) → 결합 바이트 반환."""
    with open(carrier_path, "rb") as f:
        carrier_bytes = f.read()
    ext = os.path.splitext(carrier_path)[1] or ".bin"
    return carrier_bytes + payload_bytes, ext, f"Raw 바이너리 결합 완료 (오프셋 0x{len(carrier_bytes):X})"
