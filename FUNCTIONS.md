# 함수 맵 (코드 분석용 · AI 인수인계용)

이 문서는 사람과 **다른 AI 에이전트**가 코드를 처음 볼 때 읽는 지도다. 모듈별로 어떤 함수가
무슨 일을 하는지, 입출력, 임계값, 알려진 한계를 적었다. 마지막 갱신: 2026-11-14.

## 0. 먼저 알아야 할 규칙
- **로직과 UI는 완전히 분리**: `engine`·`steganalysis`·`container`·`ioc`·`ml`·`video`·`docscan`은 UI를 import하지 않는다.
  GUI(`qt/`), CLI(`cli.py`), 격리 자식 프로세스(`sandbox_runner.py`)가 모두 `engine.scan_file()` 하나를 호출한다.
- **결과 형식 통일**: 탐지는 `result.findings`에 문자열 `"[분류/등급] 메시지"`로 쌓인다.
  등급 키워드 `CRITICAL / HIGH / WARNING / TAMPERED`가 있으면 "의심", `MEDIUM / LOW`만 있으면 "참고"(`engine._verdict`).
  추출된 데이터는 `result.carved`에 `CarvedItem`으로 쌓인다(`engine._add`).
- **선택 의존성**: Pillow, yara-python, olefile, oletools, numpy, scikit-learn, imageio-ffmpeg는 없으면 해당 기능만 꺼진다.
  추가 기능도 반드시 `try: import ... except ImportError` 패턴을 따를 것.
- **신뢰 경계**: 스캔 대상 파일은 악성일 수 있다. 크기 상한(`MAX_SCAN_FILE_BYTES`), 압축 해제 상한,
  재귀 깊이 상한을 지키고, 외부 프로그램(ffmpeg)은 별도 프로세스 + 타임아웃으로만 실행한다.
- **검증 위치**: `tests/test_detectors.py`(합성 데이터 회귀 테스트, `python tests/test_detectors.py`).
  탐지기를 고치면 반드시 실행. 실데이터 정확도는 `tools/eval_ml.py`(ML만).

## 1. 스캔 호출 흐름
```
run.py(Qt) / cli.py / sandbox_runner.py
  └─ engine.scan_file(path, password, log)                    → ScanResult
       [1] EOF 패킷·후미 데이터   crypto.find_all_offsets / parse_packet, identify_carrier_and_eof
       [2] 내부 미디어 카빙       carve_embedded_media
       [3] 픽셀/오디오/영상 LSB   inspect_lsb_carrier (카이제곱 assess)
            ├ 이미지 → _image_steganalysis: RS, WS+띠별, HCF-COM, 다중순서 LSB, ML, (JPEG) JSteg/F5
            ├ WAV    → _audio_steganalysis: 에코 은닉, 위상 코딩
            └ 영상   → _video_frames: 코덱 판별 → 무손실이면 키프레임마다 _image_steganalysis
       [4] 메타데이터/청크        inspect_metadata_and_chunks, extract_structural_payloads
       [4-C] 문서 구조            docscan.analyze_document
       [4-D] 컨테이너 틈새        container.inspect (PNG IDAT / MP4 박스)
       [5] 코드/YARA 패턴         scan_all_languages_and_deobfuscate, run_yara_or_regex_rules
       [6] 재귀 추출              _recursive_extract
       [7] 텍스트 스테그          steganalysis.text_stego_check
       [8] IOC 추출               ioc.extract_iocs → result.iocs
```

## 2. 모듈별 함수

### constants.py — 공용 상수
- `LSB_MAGIC`, `EOF_MAGIC` : 자체 은닉 패킷 매직 시그니처
- `FLAG_*` : 패킷 버전 플래그(v4/v5, 평문/암호화)
- `MAX_DECOMPRESS_BYTES`, `MAX_SCAN_FILE_BYTES` : 압축폭탄·대용량 방어 상한

### crypto.py — 패킷 직렬화·암호화·파싱 (순수 함수)
- `safe_zlib_decompress(data, max_size)` : 출력 크기 제한 zlib 해제
- `find_all_offsets(haystack, needle)` : 시그니처의 모든 출현 오프셋
- `crypt_ctr_stream(data, key, salt)` : HMAC-SHA256 기반 CTR 스트림 암·복호화
- `build_packet(magic, path, bytes, pw)` / `parse_packet(data, magic, pw)` : 패킷 생성/복원(v1~v5)
- `extract_lsb_bytes(carrier, n, sampwidth)` : LSB 비트에서 n바이트 추출(행 순서, RGB 인터리브, MSB 우선)
- `probe_lsb_packet_length(carrier, sampwidth)` : LSB 헤더로 패킷 전체 길이 산출

### analysis.py — 분석 보조
- `calc_entropy(data)` : 섀넌 엔트로피(0~8)
- `entropy_blocks(data)` : 블록별 엔트로피(차트용)
- `identify_buffer_media_type(buf)` : 매직으로 미디어 포맷 식별
- `format_hex_dump(data)` : Hex+ASCII 덤프

### embed.py — 은닉 생성 (결과 bytes 반환)
- `embed_pixelcode_lsb` / `embed_audio_wav_lsb` / `embed_eof_packet` / `embed_raw_concat`

### engine.py — 포렌식 스캔 엔진
- `scan_file(path, pw, log)` : **메인 오케스트레이터** → `ScanResult`
- `ScanResult` : filename, filepath, filesize, md5/sha1/sha256, carrier_fmt, natural_eof, overall_entropy,
  `findings`(list[str]), `carved`(list[CarvedItem]), `meta_report`(str), `log_lines`, `file_bytes`, `iocs`(dict)
- `CarvedItem` : category, format, offset(str), data(bytes), detail, name, decoded_text, id
- `_image_steganalysis(img, file_bytes, ext, findings, emit, label)` : 이미지 통계·ML 분석 묶음. 임계값:
  - RS ≥0.35 HIGH, ≥0.15 MEDIUM
  - WS ≥0.10 MEDIUM(RS가 낮을 때만)
  - 띠별 WS: 최대 띠 ≥0.12 그리고 다른 띠 중앙값의 4배 이상 → MEDIUM(국소 은닉)
  - HCF-COM 보정비 <0.75 → LOW(참고용, 이미지마다 기준이 달라 신뢰도 낮음)
  - 다중 순서 LSB 스캔 적중 → HIGH
  - ML 확률 ≥0.9 HIGH(JPEG 제외), ≥0.75 MEDIUM
  - JPEG: JSteg p ≥0.95 HIGH / ≥0.8 MEDIUM, F5 β ≥0.25 HIGH / ≥0.15 MEDIUM
- `_audio_steganalysis(raw, sampwidth, nch, findings, emit)` : 에코 z ≥10 MEDIUM, 위상 집중률 ≥0.4 HIGH / ≥0.25 MEDIUM
- `_video_frames(path, findings, emit)` : 손실 코덱이면 로그만, 무손실이면 키프레임 최대 4장 분석
- `inspect_lsb_carrier(...)` : 자체 LSB 패킷 복원 + 카이제곱(`steganalysis.assess`) + LSB 내 코드 탐지
- `identify_carrier_and_eof(data)` / `carve_embedded_media(...)` : 포맷·정상 종료지점, 내부 미디어 카빙
- `inspect_metadata_and_chunks(data, fmt)` / `extract_structural_payloads(data, fmt)` : 청크·메타·PDF 액션 코드
- `scan_all_languages_and_deobfuscate(data)` / `run_yara_or_regex_rules(data, decoded)` : 코드 시그니처·난독화 해제·룰 매칭
- `extract_strings(data, min_len, max_count)` : strings 유틸리티
- `_recursive_extract(...)` : 카빙 항목 내부 재스캔(최대 2단계, 50개)
- `build_report_dict/json/html(result)` : 단일 파일 리포트(IOC 포함)
- `_verdict(result)` → (`"의심"|"참고"|"정상"`, 대표 탐지) : 일괄 리포트 판정
- `build_batch_csv(results)` / `build_batch_html(results)` : 일괄 스캔 리포트(CSV는 UTF-8 BOM, Excel 호환)
- `diff_files(a, b)` → str : 바이트 차이 구간, 순수 후미 결합 여부, 픽셀 LSB 전용 변경 비율
- `cdr_sanitize(...)`, `bit_plane_lut_image(...)`, `query_virustotal(...)`, `set_user_yara_dir(...)`

### steganalysis.py — 통계적 스테그분석 (순수 Python, 의존성 없음)
LSB 치환(순차/무작위/소량)
- `chi_square_lsb(data)` / `chi_square_windows(data)` / `assess(carrier, lsb_sample)` : 카이제곱 PoV(순차 은닉에 강함)
- `rs_analysis(pixels, channels=3)` → 은닉률 0~1 : RS 분석(무작위 위치 은닉, 검증 0/20/50/100% → 0.00/0.22/0.51/0.97)
- `ws_analysis(pixels, w, h)` → (전체 p, [(행시작, 행끝, p)]) : Weighted Stego. 소량(3%)도 추정, 8개 수평 띠별 국소 추정 포함

LSB matching(±1)
- `lsb_matching_score(pixels, w, h)` → 비율 : 보정 HCF-COM(원본/2x2 축소본 COM 비). **참고용**(깨끗한 이미지 간 편차 0.94~1.25)

도구식 은닉
- `multi_order_lsb_scan(pixels, w, h)` → [(설정, 결과, 미리보기)] : zsteg 방식. 채널(RGB/BGR/R/G/B) × 비트0/1 ×
  MSB/LSB 우선 × 행/열 순서로 앞 256B를 뽑아 `FILE_MAGICS`(ZIP, PDF, PE, ELF, PNG, …) 또는 평문을 찾음

JPEG
- `jpeg_dct_coefficients(data, max_blocks=6000, component=None)` → [64계수 블록] : **순수 Python JPEG 엔트로피 디코더**
  (baseline + progressive, 재시작 마커 지원, 산술부호화 미지원). 이미지 위쪽부터 휘도 블록 약 max_blocks개 영역만 디코딩.
  계수는 지그재그 순서. 검증: IDCT 결과가 Pillow 픽셀과 평균 오차 0.25, baseline과 progressive 계수 완전 일치.
  내부: `_Bits`(RST 분할 비트리더), `_decode_scan`(DC/AC 최초·정밀화 스캔, EOBRUN)
- `jsteg_chi_square(blocks)` → p : 0/1 제외 AC 계수 (2k, 2k+1) 쌍 평탄화(JSteg/OutGuess 계열)
- `f5_beta(jpeg_bytes)` → β : F5 보정(calibration). 4px 잘라 같은 양자화표로 재압축한 이미지를 원본 추정치로 사용

오디오
- `pcm_to_mono(raw, sampwidth, nch)` : PCM → 첫 채널 정수 샘플
- `echo_hiding_score(samples)` → (z, lag) : 미분 신호 자기상관의 고립 피크(에코 은닉). 단일 구간 휴리스틱
- `phase_coding_score(samples)` → (비율, 세그먼트 길이) : 첫 세그먼트 FFT 위상의 ±π/2 집중률. `_fft`는 순수 Python 재귀 FFT

텍스트
- `text_stego_check(text)` → [(등급, 메시지)] : 제로폭 문자(≥8 HIGH), 줄끝 공백/탭(SNOW), 라틴·키릴/그리스 혼용 단어(동형 문자)
- `bytes_as_text(data)` → str|None : 제어문자 비율로 텍스트 여부 판정(UTF-8/UTF-16 BOM)

### container.py — 컨테이너 틈새 검사 (표준 라이브러리만)
반환 형식 공통: `(리포트 줄 list, 위협 [(등급, 메시지)], 페이로드 [dict(category, fmt, offset, data, detail, name)])`
- `inspect(data)` : **진입점**. PNG/MP4를 판별해 아래 함수로 분기
- `inspect_png(data)` : IDAT를 이어 붙여 zlib 해제 →
  zlib 종료 뒤 잔여 데이터(HIGH), 이미지 크기(`_png_raw_size`, Adam7 인터레이스 포함)보다 많이 풀리는 데이터(HIGH),
  잘못된 필터 바이트(>4, MEDIUM), IDAT 사이에 끼운 청크(MEDIUM), 표준 zlib 레벨 재현 여부(참고)
- `inspect_mp4(data)` : 최상위 박스 순회(`_boxes`, 64bit size 지원) →
  트랙 `stsz` 합계 대비 미참조 mdat(`_sample_bytes`, HIGH), 0이 아닌 free/skip(HIGH/MEDIUM), 비표준 최상위 박스(MEDIUM), 대형 uuid(LOW)
- 한계: MKV/WebM 내부, fragmented MP4(moof) 미참조 영역은 미검사

### ioc.py — IOC(침해지표) 추출
- `extract_iocs(texts, exclude_hashes, limit=200)` → {종류: [값]} : url, ipv4, email, domain, md5, sha1, sha256.
  자기 파일 해시, 0.0.0.0, W3C/Adobe/OOXML 스키마 도메인 제외. 도메인은 `_TLDS` 목록의 TLD만 인정(바이너리 잡음 억제)
- `format_iocs(iocs)` → str : 사람용 텍스트
- `python -m steg_studio.ioc` : 자체 점검

### ml.py — 머신러닝 스테그분석 (numpy + scikit-learn + 모델 파일 필요)
- `available()` : numpy가 있고 `models/spam_clf.joblib`이 존재하는지
- `spam_features(gray)` → 686차원 : SPAM(Pevný 2010). 차분을 [-3,3]으로 자르고 8방향 2차 마르코프 전이확률,
  수평·수직 4방향 평균(343) + 대각 4방향 평균(343)
- `simulate_lsbm(gray, payload, rng)` : ±1 matching 시뮬레이터(변경 확률 = payload/2)
- `simulate_hill(gray, payload, rng)` : HILL 적응형 은닉 시뮬레이터. KB 고주파 필터 → 3x3/15x15 평균으로 비용 계산 →
  삼진 엔트로피가 payload가 되도록 λ 이분탐색 → 최적 ±1 변경 확률. 이미지당 약 1.7초
- `predict(img)` → (확률, 설명)|None : 흑백 변환 후 512px 타일(최대 16개)별 확률의 최댓값
- 모델 정보: 로지스틱 회귀(StandardScaler 포함). BOSSbase 1,600장 학습 / 400장 테스트.
  MEDIUM ≥0.75: 오탐 2.5%, LSBM 0.1/0.2/0.4bpp 62.5/79.5/85.8%, HILL 0.2/0.4bpp 10/20%.
  HIGH ≥0.9: 오탐 0.2%. 상세는 `steg_studio/models/spam_report.txt`
- 한계: 흑백·무압축 학습이라 컬러/JPEG에서는 분포가 달라져 MEDIUM까지만 보고. 적응형 은닉 탐지는 약함

### video.py — 영상 프레임 (imageio-ffmpeg)
- `ffmpeg_exe()` : imageio-ffmpeg 번들 바이너리 경로(없으면 PATH의 ffmpeg)
- `probe_codec(path)` → 코덱명|None : `ffmpeg -i` 출력 파싱(타임아웃 30초)
- `LOSSLESS_CODECS` : ffv1, huffyuv, ffvhuff, png, rawvideo, utvideo, magicyuv, qtrle 등
- `extract_keyframes(path, max_frames=4)` → (임시폴더, [png 경로]) : I-frame만 추출(`-fps_mode vfr`; ffmpeg 7+에서 `-vsync`는 폐지됨).
  호출자가 임시폴더를 삭제
- 설계 판단: 손실 코덱은 압축 과정에서 LSB가 보존되지 않으므로 프레임 LSB 분석을 하지 않는다

### docscan.py — 문서형(HWP/Office/OOXML) 분석
- `analyze_document(data, ext)` : **진입점** → (리포트, 위협, 페이로드)
- `detect_document_type` / `_analyze_ole` / `_analyze_zip_office` / `_analyze_vba` / `_scan_suspicious`

### sandbox.py / sandbox_runner.py — 프로세스 격리 스캔
- `run_scan_isolated(path, pw, timeout, mem_limit_mb, on_log)` : 자식 프로세스에서 스캔, 결과는 pickle로 전달
- `_apply_windows_job_limits` (Windows Job Object) / `_posix_preexec` (setrlimit) / `_maybe_firejail`

### cli.py / __main__.py — 명령줄 (`python -m steg_studio <명령>`)
- `scan FILE [--isolated] [--json P] [--html P] [--quiet]` : 종료코드 1 = 탐지 있음
- `embed CARRIER PAYLOAD [-o] [--password] [--mode pixelcode|audio_lsb|eof_packet|raw_concat]`
- `sanitize FILE [-o]` : CDR 무해화
- `batch FOLDER [-r] [--csv P] [--html P]` : 일괄 스캔. 종료코드 1 = 의심 파일 존재 (`_cmd_batch`)
- `diff ORIGINAL SUSPECT` : 원본 대조 (`_cmd_diff` → `engine.diff_files`)

### qt/ — PySide6 GUI (로직은 위 모듈 호출만)
- `main_window.MainWindow` : 탭 조립 + 테마 + 탭 간 연동
- `scan_tab.ScanTab` : 스캐너(목록/로그/코드·이미지·비트평면·엔트로피·strings/메타 + CDR·리포트·격리). IOC·컨테이너 결과는 메타 탭에 표시
- `embed_tab.EmbedTab` : 은닉 UI
- `batch_tab.BatchTab` : 폴더 일괄 스캔 + CSV/HTML 리포트 저장(`_export`), 문서·txt 확장자 포함
- `settings_tab`, `entropy_chart`, `workers`(ScanWorker/VtWorker/BatchWorker), `theme`, `config`

## 3. 도구 · 테스트 · 데이터
- `tests/test_detectors.py` : RS/WS, JPEG 디코더(baseline=progressive), 다중순서 스캔, 오디오·텍스트, PNG IDAT, IOC 회귀 테스트
- `tools/train_ml.py <pgm폴더> [--n 2000] [--workers N]` : SPAM 분류기 학습 → `steg_studio/models/spam_clf.joblib`.
  이미지 단위 70/10/20 분할, 검증 균형정확도로 logreg/HistGradientBoosting 중 선택. 2,000장 기준 약 23분(11코어)
- `tools/eval_ml.py <pgm폴더>` : 같은 분할의 테스트셋에서 임계값별 오탐률/탐지율 표
- 데이터셋: `E:\stego_datasets\bossbase\BOSSbase_1.01.zip`(1.67GB, 10,000장) + `pgm2000\`(무작위 2,000장, 0.51GB)

## 4. 알려진 한계 (다음 작업 후보)
- 적응형 은닉(HILL/S-UNIWARD) 탐지율이 낮음 → SRM 전체 특징(약 34,671차원) + 앙상블 FLD, 또는 CNN(SRNet, GPU 필요)
- ML과 통계 임계값은 흑백 BOSSbase와 합성 데이터 기준 → 실제 컬러/JPEG 사진으로 오탐률 측정·재보정 필요
- 노이즈가 많은 WAV에서 카이제곱 오탐 → 실제 음원으로 임계값 보정
- 에코 탐지는 단일 구간 → 구간별 켑스트럼 분석으로 고도화
- diff는 CLI 전용(GUI 탭 없음), MKV 내부 구조 틈새 검사 없음
