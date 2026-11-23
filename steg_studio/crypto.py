"""
은닉 패킷 직렬화 · 암호화 · 파싱 코어 (GUI 비의존 순수 함수).

이 모듈은 tkinter 등 UI와 완전히 분리되어 있어 단위 테스트가 가능합니다.
- build_packet()   : 숨길 파일을 zlib 압축 + PBKDF2 키유도 + HMAC-CTR 암호화 + AAD HMAC 서명 패킷으로 직렬화
- parse_packet()   : v1~v5 은닉 패킷 복호화 및 원본 복원 (듀얼 폴백 파서)
- crypt_ctr_stream(): HMAC-SHA256 기반 CTR 스트림 암호화/복호화 공통 함수
- LSB 추출 및 패킷 길이 탐침 유틸리티 포함
"""

import os
import zlib
import hmac
import struct
import hashlib

from .constants import (
    LSB_MAGIC,
    FLAG_PLAIN_V4,
    FLAG_ENCRYPTED_V4,
    FLAG_PLAIN_V5_AAD,
    FLAG_ENCRYPTED_V5_AAD,
    MAX_DECOMPRESS_BYTES,
)


def safe_zlib_decompress(compressed_data: bytes, max_size: int = MAX_DECOMPRESS_BYTES) -> bytes:
    """압축 폭탄(Decompression Bomb) 방어를 위해 출력 크기를 max_size로 엄격히 제한합니다."""
    dobj = zlib.decompressobj()
    out = dobj.decompress(compressed_data, max_size)
    if dobj.unconsumed_tail:
        raise ValueError(f"압축 해제 결과가 안전 상한선({max_size:,} bytes)을 초과하여 차단되었습니다 (Decompression Bomb 방어).")
    out += dobj.flush()
    return out


def find_all_offsets(haystack: bytes, needle: bytes, start_pos: int = 0) -> list:
    """파일 내 시그니처가 여러 번 나타날 때 앞쪽 가짜 시그니처에 속지 않도록 모든 오프셋을 반환합니다."""
    offsets = []
    pos = start_pos
    while True:
        idx = haystack.find(needle, pos)
        if idx == -1:
            break
        offsets.append(idx)
        pos = idx + 1
    return offsets


def crypt_ctr_stream(data: bytes, key: bytes, salt: bytes) -> bytes:
    """HMAC-SHA256 기반 CTR(Counter) 모드 스트림 암호화/복호화 공통 함수."""
    out = bytearray(len(data))
    block_count = (len(data) + 31) // 32
    mv = memoryview(data)
    for counter in range(block_count):
        ks = hmac.new(key, salt + struct.pack(">I", counter), hashlib.sha256).digest()
        start = counter * 32
        end = min(start + 32, len(data))
        chunk = mv[start:end]
        for i in range(end - start):
            out[start + i] = chunk[i] ^ ks[i]
    return bytes(out)


def build_packet(magic: bytes, file_path: str, raw_bytes: bytes, password: str = "") -> bytes:
    """
    [은닉 패킷 생성 함수]
    숨길 파일(코드/이미지 등)을 압축하고 헤더·파일명·본문을 묶어 v5 보안 패킷으로 직렬화합니다.
    - magic: LSB 은닉 시 b"PXCD", EOF 결합 시 b"__STEG_EOF__"
    - v5 패킷 구조:
      [Magic] + [Header(>BHI: flags, fname_len, block_len)] + [Filename] + [SHA-256] + [Payload Block]
    - 헤더(flags, fname_len)와 파일명(fname_bytes)까지 모두 Associated Data(AAD)로 묶어 HMAC/해시 검증에 포함.
    - 공격자가 파일명이나 헤더 바이트를 변조하면 복호화 및 무결성 검증 단계에서 즉시 탐지됨.
    """
    fname_bytes = os.path.basename(file_path).encode("utf-8")
    compressed = zlib.compress(raw_bytes, level=9)
    aad_prefix = magic + struct.pack(">H", len(fname_bytes)) + fname_bytes

    if password:
        flags = FLAG_ENCRYPTED_V5_AAD
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, dklen=32)
        payload_hash = hashlib.sha256(raw_bytes).digest()
        enc_body = crypt_ctr_stream(compressed, key, salt)
        # AAD(매직 + 플래그 + 파일명길이 + 파일명) + Salt + 원본해시 + 암호문 전체에 대해 HMAC 서명
        aad_full = magic + struct.pack(">BH", flags, len(fname_bytes)) + fname_bytes + salt + payload_hash + enc_body
        auth_mac = hmac.new(key, aad_full, hashlib.sha256).digest()
        payload_block = salt + auth_mac + enc_body
    else:
        flags = FLAG_PLAIN_V5_AAD
        # 평문 모드에서도 파일명 변조를 감지할 수 있도록 (AAD + 원본 바이트) 결합 해시 저장
        payload_hash = hashlib.sha256(aad_prefix + raw_bytes).digest()
        payload_block = compressed

    header = struct.pack(">BHI", flags, len(fname_bytes), len(payload_block))
    return magic + header + fname_bytes + payload_hash + payload_block


def parse_packet(data: bytes, magic: bytes, password: str = ""):
    """
    듀얼 폴백 파서:
    1) v4 / v5 포맷 (>BHI: flags, fname_len, block_len) 시도
    2) 실패 시 구버전 v1~v3 포맷 (>HI: fname_len, comp_len) 자동 폴백 시도
    """
    if not data.startswith(magic):
        return None
    base_off = len(magic)

    # [1차 시도] v4 / v5 포맷 파싱
    if len(data) >= base_off + 7:
        flags, fname_len, block_len = struct.unpack(">BHI", data[base_off:base_off + 7])
        if flags in (FLAG_PLAIN_V4, FLAG_ENCRYPTED_V4, FLAG_PLAIN_V5_AAD, FLAG_ENCRYPTED_V5_AAD):
            total_needed = base_off + 7 + fname_len + 32 + block_len
            if 0 < fname_len <= 512 and 0 < block_len <= MAX_DECOMPRESS_BYTES and len(data) >= total_needed:
                res = _try_parse_v4_v5(data, magic, base_off, flags, fname_len, block_len, password)
                if res is not None:
                    return res

    # [2차 폴백 시도] 구버전(v1 ~ v3) 포맷 파싱 (>HI: fname_len, comp_len)
    if len(data) >= base_off + 6:
        fname_len_v1, comp_len_v1 = struct.unpack(">HI", data[base_off:base_off + 6])
        total_needed_v1 = base_off + 6 + fname_len_v1 + 32 + comp_len_v1
        if 0 < fname_len_v1 <= 512 and 0 < comp_len_v1 <= MAX_DECOMPRESS_BYTES and len(data) >= total_needed_v1:
            try:
                off = base_off + 6
                fname = data[off:off + fname_len_v1].decode("utf-8", errors="replace")
                off += fname_len_v1
                expected_hash = data[off:off + 32]
                off += 32
                compressed = data[off:off + comp_len_v1]
                raw_data = safe_zlib_decompress(compressed)
                actual_hash = hashlib.sha256(raw_data).digest()
                return {
                    "version": "v1~v3 (Legacy)",
                    "filename": fname,
                    "payload": raw_data,
                    "compressed_size": comp_len_v1,
                    "original_size": len(raw_data),
                    "sha256_hex": actual_hash.hex(),
                    "integrity_ok": (expected_hash == actual_hash),
                    "encrypted_locked": False,
                    "total_packet_bytes": total_needed_v1
                }
            except Exception:
                pass

    return None


def _try_parse_v4_v5(data: bytes, magic: bytes, base_off: int, flags: int, fname_len: int, block_len: int, password: str):
    try:
        off = base_off + 7
        fname_raw = data[off:off + fname_len]
        fname = fname_raw.decode("utf-8", errors="replace")
        off += fname_len
        expected_hash = data[off:off + 32]
        off += 32
        payload_block = data[off:off + block_len]
        total_pkt_len = off + block_len

        is_encrypted = flags in (FLAG_ENCRYPTED_V4, FLAG_ENCRYPTED_V5_AAD)
        is_v5_aad = flags in (FLAG_PLAIN_V5_AAD, FLAG_ENCRYPTED_V5_AAD)
        ver_str = "v5 (AAD 보호)" if is_v5_aad else "v4"

        if is_encrypted:
            if len(payload_block) < 48:
                return None
            if not password:
                return {
                    "version": ver_str,
                    "filename": fname,
                    "payload": b"",
                    "compressed_size": block_len,
                    "original_size": 0,
                    "sha256_hex": expected_hash.hex(),
                    "integrity_ok": False,
                    "encrypted_locked": True,
                    "total_packet_bytes": total_pkt_len
                }
            salt = payload_block[:16]
            auth_mac = payload_block[16:48]
            enc_body = payload_block[48:]
            key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, dklen=32)

            if is_v5_aad:
                aad_full = magic + struct.pack(">BH", flags, fname_len) + fname_raw + salt + expected_hash + enc_body
                calc_mac = hmac.new(key, aad_full, hashlib.sha256).digest()
            else:
                calc_mac = hmac.new(key, salt + expected_hash + enc_body, hashlib.sha256).digest()

            if not hmac.compare_digest(auth_mac, calc_mac):
                return {
                    "version": ver_str,
                    "filename": fname,
                    "payload": b"",
                    "compressed_size": block_len,
                    "original_size": 0,
                    "sha256_hex": expected_hash.hex(),
                    "integrity_ok": False,
                    "encrypted_locked": True,
                    "wrong_password_or_tampered": True,
                    "total_packet_bytes": total_pkt_len
                }
            compressed = crypt_ctr_stream(enc_body, key, salt)
            raw_data = safe_zlib_decompress(compressed)
            actual_hash = hashlib.sha256(raw_data).digest()
            integrity_ok = (expected_hash == actual_hash)
        else:
            raw_data = safe_zlib_decompress(payload_block)
            if is_v5_aad:
                aad_prefix = magic + struct.pack(">H", fname_len) + fname_raw
                calc_hash = hashlib.sha256(aad_prefix + raw_data).digest()
                integrity_ok = (expected_hash == calc_hash)
            else:
                calc_hash = hashlib.sha256(raw_data).digest()
                integrity_ok = (expected_hash == calc_hash)
            actual_hash = hashlib.sha256(raw_data).digest()

        return {
            "version": ver_str,
            "filename": fname,
            "payload": raw_data,
            "compressed_size": block_len,
            "original_size": len(raw_data),
            "sha256_hex": actual_hash.hex(),
            "integrity_ok": integrity_ok,
            "encrypted_locked": False,
            "total_packet_bytes": total_pkt_len
        }
    except Exception:
        return None


def extract_lsb_bytes(raw_carrier: bytes, num_bytes: int, sampwidth: int = 1) -> bytes:
    """sampwidth 간격으로 각 샘플의 최하위 유효 바이트(LSB)에서 비트를 추출합니다."""
    out = bytearray(num_bytes)
    sample_idx = 0
    for i in range(num_bytes):
        val = 0
        for _ in range(8):
            val = (val << 1) | (raw_carrier[sample_idx * sampwidth] & 1)
            sample_idx += 1
        out[i] = val
    return bytes(out)


def probe_lsb_packet_length(raw_carrier: bytes, sampwidth: int = 1) -> int:
    """LSB 헤더(초반 48바이트)를 읽어 v1~v3 또는 v4~v5 패킷의 전체 바이트 길이를 계산합니다."""
    max_avail_bytes = (len(raw_carrier) // sampwidth) // 8
    if max_avail_bytes < 48:
        return 0
    hdr = extract_lsb_bytes(raw_carrier, 48, sampwidth=sampwidth)
    if not hdr.startswith(LSB_MAGIC):
        return 0

    # v4/v5 헤더 확인
    flags, fname_len, block_len = struct.unpack(">BHI", hdr[4:11])
    if flags in (FLAG_PLAIN_V4, FLAG_ENCRYPTED_V4, FLAG_PLAIN_V5_AAD, FLAG_ENCRYPTED_V5_AAD):
        total_len = 11 + fname_len + 32 + block_len
        if 0 < fname_len <= 512 and 0 < block_len <= MAX_DECOMPRESS_BYTES and total_len <= max_avail_bytes:
            return total_len

    # v1~v3 레거시 헤더 확인
    fname_len_v1, comp_len_v1 = struct.unpack(">HI", hdr[4:10])
    total_len_v1 = 10 + fname_len_v1 + 32 + comp_len_v1
    if 0 < fname_len_v1 <= 512 and 0 < comp_len_v1 <= MAX_DECOMPRESS_BYTES and total_len_v1 <= max_avail_bytes:
        return total_len_v1

    return 0
