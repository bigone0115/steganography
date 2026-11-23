"""
스테가노그래피/포렌식 스튜디오 공용 상수 정의.

- 은닉 패킷 매직 시그니처
- 패킷 버전 플래그
- 메모리 보호 상한선 (압축 폭탄 / 대용량 파일 방어)
"""

# 패킷 매직 시그니처
LSB_MAGIC = b"PXCD"               # 이미지/오디오 LSB 은닉 패킷
EOF_MAGIC = b"__STEG_EOF__"       # 파일 끝(EOF) 결합 패킷

# 패킷 버전 플래그
FLAG_PLAIN_V4 = 0x00
FLAG_ENCRYPTED_V4 = 0x01
FLAG_PLAIN_V5_AAD = 0x02          # v5 평문 + 헤더 무결성 검증
FLAG_ENCRYPTED_V5_AAD = 0x03      # v5 암호화 + 파일명/헤더 전체 HMAC(AAD) 보호

# 압축 폭탄(Decompression Bomb) 및 대용량 파일 메모리 보호 상한선
MAX_DECOMPRESS_BYTES = 32 * 1024 * 1024    # 최대 압축 해제 허용 크기: 32 MB
MAX_SCAN_FILE_BYTES = 256 * 1024 * 1024    # 단일 파일 로드 상한선: 256 MB
