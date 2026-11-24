# 작업 기록 (CHANGELOG)

Stego & Forensic Security Studio — 단일 파일 도구에서 모듈형 크로스플랫폼 앱으로 발전한 기록.
최신 작업이 위에 옵니다. (관련 문서: [README](README.md) · [FUNCTIONS](FUNCTIONS.md) · [ROADMAP](ROADMAP.md))

---

## 2026-11-24 (4) — 웹 UI(도커)에서 디렉터리 일괄 스캔 제외

- 웹 UI 탭을 **정밀 포렌식 스캐너 / 메타데이터 / 설정** 3개로 정리. 브라우저로 폴더를 통째로 업로드하는 방식은
  대용량·장시간 작업에 무리라 제외하고, 대량 점검은 데스크톱 GUI 일괄 스캔·CLI `batch -j N`으로 역할 분리.
- 웹 서버의 병렬 분석(여러 사용자 요청 동시 처리)은 유지. 데스크톱 GUI·CLI 일괄 스캔은 변경 없음.

## 2026-11-24 (3) — 압축·디스크 이미지 내부 파일 정밀 스캔 (탐지 누락 수정)

### 수정
- **ZIP 안의 스테가노그래피 이미지가 '정상'으로 누락**되던 문제. 원인 3가지:
  ① ZIP 계열은 문서 내부 정상 이미지 오탐 방지를 위해 시그니처 카빙을 EOCD 이후만 수행,
  ② 일반 ZIP은 문서 분석기가 열지 않음, ③ **재귀 추출은 카빙·문서·전달포맷만 보고 픽셀 LSB·통계·ML 스테그분석은 최상위 파일에만 적용**.
- 스캔 **[6-B] 단계** 추가: ZIP(일반·DOCX/HWPX 등 문서형의 비XML 파트)·ISO 내부 파일을 꺼내 `scan_file` **전체 단계로 재검사**하고
  결과를 `[내부:경로]`로 병합(등급 유지 → 최종 판정 반영). 숨긴 파일 복원 항목도 뷰어에 추가.
- 안전 상한: 중첩 깊이 2단계(초과 시 MEDIUM 경보 — 다중 중첩은 검사 회피 수법), 항목 200개, 파일 1개 64MB·합계 256MB(압축 폭탄 방어),
  암호화 항목은 '검사 불가' 표시, 손상 항목은 경보.
- 기존 샘플 15종 판정 변화 없음(DOCX 내부 스크립트 파트에 정보성 경보 1건 추가). 회귀 테스트 2종 추가 — 49/49 통과.

## 2026-11-24 (2) — 공격 전달 포맷 + 속도·처리량

### 추가 — 공격 전달 포맷 분석 (`delivery.py`, 스캔 [4-F])
- **RTF**: `\objdata` OLE 객체 디코딩(제어어 끼워 넣기 난독화 무시), 수식 편집기 객체(CVE-2017-11882/2018-0802),
  OLE2Link/htmlfile(CVE-2017-0199 계열), Package 포장 파일 추출, `\objupdate` 자동 갱신, 링크 객체, 원격 템플릿 주입, DDEAUTO 필드.
- **LNK 바로가기**: 대상·인수·아이콘·작업 폴더 해석, LOLBin(powershell/mshta/rundll32 등) 실행, `-enc`·숨김 창·다운로드·IEX 인수,
  네트워크 공유/WebDAV 대상, 인수 공백 패딩, 최소화 실행, 아이콘 위장. 구조 종료 지점 계산으로 **덧붙인 페이로드 탐지**.
- **ISO/IMG 디스크 이미지**: ISO 9660(+Joliet) 파일 목록·숨김 속성 해석, 내부 파일 추출 → 재귀 스캔(ISO 안 LNK까지 분석),
  "보이는 LNK + 숨김 DLL" 조합 CRITICAL. ISO 내부는 시그니처 중복 카빙 생략. **VHD/VHDX** 식별.
- 회귀 테스트 3종(무해한 합성 RTF·LNK·ISO) — 47/47 통과.

### 개선 — 속도 (결과 동일성 검증 후 적용)
- `extract_strings` 정규식화, `calc_entropy` numpy 빈도, WS 분석 numpy 벡터화(없으면 기존 순수 Python), PNG zlib 재현 검사 4MB 초과 생략.
- 6MP PNG **12.8s → 4.1s**, 10MB 바이너리 **2.7s → 0.3s**, 5MB 텍스트 1.9s → 1.3s.

### 개선 — 처리량 (병렬)
- `engine.scan_many`: 프로세스 풀(작업자당 모델 1회 로드) / 격리 모드는 격리 자식 프로세스 N개 동시. 기본 코어 절반·최대 8.
- CLI `batch -j N`, GUI 일괄 스캔(격리 유지), 웹 서버(요청 스레드 + 스캔 프로세스 풀, 웹 일괄 탭 동시 업로드 3개).
- 21개 파일 일괄 스캔 **27.7s → 4.5s**(판정 동일), 웹 6MP 사진 6장 동시 약 17s → 5.5s.
- 작업자는 부모 감시 — 서버/CLI가 강제 종료돼도 고아 프로세스로 남지 않음. 수치 라이브러리 스레드 1개 고정(과부하 방지).

## 2026-11-24 — JPEG 전용 ML 스테그분석 (DCTR)

### 추가
- **DCTR 8000차원 특징**(Holub & Fridrich 2015) — 양자화 DCT 계수 → 비반올림 복원 → 64 DCT 기저 비데시메이트 응답 히스토그램.
  기존 공간 모델은 JPEG에서 오탐이 나 건너뛰던 공백을 메움. `ml.dctr_features`, `ml.predict_jpeg`, 스캔 JPEG 분기에 연결.
- **QF별 모델**: 양자화표로 QF 추정 → 가장 가까운 학습 QF 모델 사용. ±3 밖·비표준 표는 "학습 범위 밖"으로 판정 생략(오탐 방지).
- **학습용 JPEG 시뮬레이터**(메모리상 계수만 변경, 파일 미생성): nsF5, UERD, J-UNIWARD(db8, 직접 계산 대조 일치).
- 학습 `tools/train_jpeg.py <BOSSbase> [--qfs 75,90]` → `models/jpeg_clf.joblib` + `jpeg_report.txt`.
- 회귀 테스트 1종 추가 (44/44 통과). **모델은 아직 미학습**(BOSSbase 필요) — 모델 파일이 없으면 기능만 조용히 비활성.

## 2026-11-23 — 메타데이터 2차: 잔존 검사 · 포렌식 · pikepdf · 신규 포맷

### 추가
- **원본 값 잔존 검사**: 스크럽 후 원본 메타 '값'을 결과 바이트(ZIP 파트·PDF Flate 스트림 해제 포함, UTF-8/16)에서 직접 검색.
  리더가 모르는 위치(customXml 등)의 누출을 "잔여 없음"으로 오판하지 않음.
- **포렌식(편집·조작 흔적)** — `scan`·`meta`·GUI 메타 탭에 경보로 표시:
  EXIF 썸네일 ≠ 본 이미지(크롭·합성), 촬영시각 vs 수정시각 역전/차이, 편집 도구(Photoshop 등) 흔적,
  PDF 증분 업데이트 횟수·판마다 다른 Producer·ModDate < CreationDate, Office/HWPX 수정일 < 작성일,
  ZIP 일부 파트만 다른 저장 시각(외부 도구 삽입).
- **PDF 전체 재작성(pikepdf, 선택)**: /Info·XMP(압축 포함)·PieceInfo·주석 작성자 제거 + 증분 업데이트 이전 판 정리.
  편집도 길이 제한 없음. pikepdf 없거나 암호화면 기존 길이보존 방식으로 폴백. 압축 XMP 읽기 지원.
- **신규 포맷**: HWPX(content.hpf 작성자/저장자/일시, 변경추적 작성자), HEIC/AVIF(Exif·XMP 아이템을 같은 길이로 비움 —
  플러그인 불필요), WebP(EXIF/XMP 청크 + VP8X 플래그), WAV(LIST/INFO·BWF bext·iXML·id3·XMP), TIFF(같은 압축으로 무손실 재저장,
  DNG·JPEG압축 TIFF는 거부). 동영상 GPS(©xyz/ISO6709) 표시.
- PNG 스크럽: 비표준/private 부가 청크도 제거(색·투명도·APNG 청크는 유지).
- 회귀 테스트 8종 추가 (43/43 통과). `requirements.txt`에 pikepdf(선택) 추가.

## 2026-11-22 — 메타데이터 편집/스크럽 강화 (`metaedit.py`, `engine.py`)

### 수정 (누출·손상 버그)
- **PDF**: 증분 업데이트 파일에서 첫 /Info만 바꾸던 문제 → 모든 판의 /Info를 교체. 비압축 XMP 패킷도 스크럽.
  잘린 값이 `\`로 끝나 `)`를 먹던 구조 파손 방지, 16진 값은 FEFF BOM(UTF-16BE) 규격으로 기록·해석.
- **JPEG**: 스크럽이 ICC(APP2)·Adobe(APP14)까지 지워 CMYK/색이 깨지던 문제 → 유지. EXIF 편집은 재인코딩 없이 APP1만 교체(무손실).
  GPS 좌표·본체일련번호 등 서브 IFD 항목도 편집/삭제 가능(이전엔 조용히 무시).
- **MP4**: udta 삭제로 faststart 파일의 stco 오프셋이 어긋나던 문제 → 같은 크기 `free` 박스로 무력화(크기 불변).
  moov/meta·XMP uuid 박스와 mvhd/tkhd/mdhd 생성·수정 시각까지 제거. HEIC/AVIF는 MP4로 오인하지 않음.
- **MP3**: ID3v2.4 synchsafe 프레임 크기, v2.3 헤더에 UTF-8 쓰던 규격 위반, 중복 프레임(APIC 등) 소실 수정. APE 태그도 스크럽.
- **OOXML**: custom.xml 사용자 정의 속성, 댓글·변경추적 작성자(word/xl/ppt), ZIP 엔트리 시각까지 스크럽. 스크럽은 빈 값 대신 요소 삭제.

### 추가
- 스크럽 후 자동 재검사 — 결과에 "잔여 메타 없음" 또는 남은 키 목록 표시.
- 편집에서 값을 비우면 해당 필드 삭제. 적용 못 한 키는 '미적용'으로 알림.
- CLI `meta` 명령: `python -m steg_studio meta <파일> [--scrub | --set KEY=VALUE ...] [-o 출력]`.
- 회귀 테스트 5종 추가 (35/35 통과).

## 2026-11-14 (3차) — ML 스테그분석 · 영상 프레임

### 추가
- **ML 스테그분석(`ml.py`)** — SPAM686 특징 + 로지스틱 회귀(HistGradientBoosting보다 검증 성능 우수).
  학습 `tools/train_ml.py`, 임계값 평가 `tools/eval_ml.py`. 모델 `steg_studio/models/spam_clf.joblib`(23KB).
  BOSSbase 2,000장(1,600 학습 / 400 테스트) × 원본 + LSBM 0.1/0.2/0.4 + HILL 0.2/0.4 시뮬레이션.

  | 기준 | 오탐률 | LSBM 0.1/0.2/0.4 | HILL 0.2/0.4 |
  |---|---|---|---|
  | MEDIUM ≥0.75 | 2.5% | 62.5/79.5/85.8% | 10.0/20.0% |
  | HIGH ≥0.9 | 0.2% | 44.0/61.8/74.2% | 5.2/11.8% |

  ±1 matching은 실용 수준, 적응형(HILL)은 여전히 약함. JPEG/컬러 원본은 학습 조건과 달라 MEDIUM까지만 보고.
- **영상 프레임 분석(`video.py`)** — imageio-ffmpeg로 코덱 판별 → 무손실(FFV1/HuffYUV/PNG 등)이면 키프레임
  추출 후 이미지 분석 전체 적용. 손실 코덱은 LSB가 보존되지 않아 분석 생략(로그로 명시).
- 의존성: numpy, scikit-learn(+scipy), imageio-ffmpeg — 모두 선택 사항, 없으면 해당 기능만 비활성.
- 데이터셋: `E:\stego_datasets\bossbase` (zip 1.67GB + 추출 2,000장 0.51GB).

## 2026-11-14 (2차) — 약점 보강

### 수정한 버그
- **JPEG 디코더 바이트 스터핑 버그** — `FF00`을 `FF`가 아닌 빈 값으로 지워 계수가 중간부터 틀어지던 문제.
  1차의 JSteg/F5 수치는 이 버그 영향을 받았음. 수정 후 IDCT 대조 오차 0.25(반올림 수준). JSteg MEDIUM(p≥0.8) 구간 추가.

### 추가
- **progressive JPEG** 디코딩 (DC/AC 최초·정밀화 스캔, EOBRUN, 재시작 마커). baseline과 계수 완전 일치 검증.
- **WS 분석 + 띠별 국소 분석** — 소량 은닉 추정(3% → 0.031~0.033), 순차 은닉 3%는 첫 띠만 0.15~0.23으로 튐.
- **HCF-COM(±1 LSB matching)** — 참고 수치로만 사용. 깨끗한 이미지 간 편차(0.94~1.25)가 커서 0.75 미만만 LOW 보고.
- **다중 순서 LSB 스캔(zsteg 방식)** — 채널조합×비트0/1×MSB/LSB우선×행/열 순서로 파일 시그니처·평문 탐지.
- **컨테이너 틈새 검사(`container.py`, 스캔 [4-D])** — PNG: zlib 뒤 잔여, 초과 해제 데이터, 잘못된 필터 바이트,
  IDAT 사이 끼운 청크. MP4: 미참조 mdat 영역, 0 아닌 free/skip, 비표준 최상위 박스.
- **회귀 테스트** `tests/test_detectors.py` (합성 데이터, `python tests/test_detectors.py`).

### 보류 (다운로드 승인 필요)
- SRM 특징 + 분류기(numpy/scikit-learn + BOSSbase 등 학습 데이터), 영상 프레임 추출(ffmpeg).

## 2026-11-14

### 탐지 강화 1순위
- **IOC 추출(`ioc.py`)** — URL/IPv4/도메인/이메일/MD5·SHA-1·SHA-256. 파일 문자열·추출 항목·디코딩 코드 전체 대상.
  스캔 [8]단계, JSON/HTML 리포트·메타 탭에 표시. 자기 파일 해시·W3C/Adobe 등 잡음 도메인 제외.
- **RS 분석(`steganalysis.rs_analysis`)** — 무작위 위치 LSB 은닉까지 탐지 + 은닉률 추정 (검증: 0/20/50/100% → 0.00/0.22/0.51/0.97).
- **일괄 스캔 리포트** — 일괄 탭 CSV(Excel 한글 호환)/HTML 저장 버튼, CLI `batch` 서브커맨드. 일괄 대상에 문서·txt 확장자 추가.

### 탐지 강화 2순위
- **JPEG DCT 분석** — 순수 Python baseline JPEG 디코더로 계수 추출 → JSteg 카이제곱(검증 0.00→0.97),
  F5 보정(calibration) β 추정(정상 ≈0.03 / β=0.3 은닉 ≈0.3). progressive JPEG은 건너뜀.
- **텍스트 스테그(스캔 [7]단계)** — 제로폭 문자, 줄끝 공백/탭(SNOW), 라틴·키릴 혼용(homoglyph).
- **오디오 에코/위상 코딩** — 미분 신호 자기상관 피크(에코, z≥10), 첫 세그먼트 ±π/2 위상 집중률(위상 코딩).
- **파일 비교** — CLI `diff 원본 의심본`: 바이트 차이 구간, 순수 후미 결합 판별, 픽셀 LSB 전용 변경 비율.

### 알려진 한계
- 합성 노이즈 WAV는 기존 카이제곱 검사에서 오탐(LSB가 원래 무작위). 실제 음원으로 임계값 보정 필요.
- 에코 탐지는 단일 구간 휴리스틱 — 구간마다 지연이 바뀌는 방식은 켑스트럼 분석으로 고도화 여지.
- diff는 CLI 전용(GUI 탭 미추가).

## 2026-11-13

### 탐지 능력 강화 (A)
- **통계적 스테그분석(`steganalysis.py`)** — 카이제곱(Chi-square) PoV 공격을 순수 Python으로 구현
  (scipy 없이 불완전 감마함수 직접). 구간 윈도우 방식으로 부분/순차 은닉도 포착.
  우리 패킷(PXCD)이 아니어도 **범용 LSB 은닉**을 통계로 탐지. (검증: 깨끗 0.0 / 은닉 1.0)
- **사용자 YARA 룰 로딩** — 설정에서 `.yar` 폴더 지정 → 내장 룰과 함께 매칭(mtime 캐시).
- **재귀 추출** — 카빙 항목 내부를 재스캔(최대 2단계). PNG 속 ZIP 속 docx까지 추출.
- **HWP BinData zlib 해제 후 재검사** — 압축 뒤에 숨긴 PE/EPS/스크립트 노출.

### 문서형 악성코드 분석 (`docscan.py`)
- **HWP 5.x · DOC · XLS · PPT**(OLE 복합문서, olefile), **HWPX · DOCX · XLSX · PPTX**(ZIP),
  **VBA 매크로**(oletools, 자동실행/의심 키워드) 해석.
- `identify_carrier_and_eof`가 문서 포맷을 인식(이전엔 "일반 바이너리"로 처리됨).

### UX / 설정
- **설정 탭 신설** — 다크/화이트 **테마 전환**, VirusTotal 키 저장, 격리 타임아웃/메모리 상한,
  strings 최소 길이, 기본 저장 폴더, YARA 룰 폴더. QSettings로 OS 표준 위치에 영구 저장.
- **은닉 기법 선택 가독성 개선** — 선택 항목 강조(테두리/배경/볼드) + "현재 선택" 라벨.

### 크로스플랫폼 / CLI
- **CLI(`cli.py`, `__main__.py`)** — `python -m steg_studio` (scan/embed/sanitize). 서버·자동화·무GUI 환경 지원.
- **프로세스 격리 플랫폼 분기** — Windows=Job Object, Linux/macOS=setrlimit(+firejail).

### 상용화 준비 / 문서
- **ROADMAP.md** — 6단계 상용화 로드맵(수익모델 미정/내부용 기준). 
- **FUNCTIONS.md** — 모듈·함수 맵(코드 분석용). 함수별 docstring 보강.

### 보안 격리 (앞서)
- **2중 샌드박스** — ① 프로세스 격리 스캔(크래시/자원고갈 방어, 기본 ON) ② Windows Sandbox(`sandbox.wsb`).

### 기능 완성도 (A/B 1차)
- 리포트 내보내기(HTML/JSON), 일괄→스캐너 연동(더블클릭), 구조 내부 코드 노출 확장,
  드래그&드롭, 다중 해시(MD5/SHA-1/SHA-256) 복사, 문자열(strings) 추출, 진행률 표시.

### 비트평면 · 엔트로피 · CDR
- 비트 평면 시각화, 구간별 엔트로피 차트(QPainter), CDR 무해화(이미지 재인코딩/WAV LSB 초기화/후미 절단) Qt 포팅.

### GUI 전면 전환 (tkinter → PySide6/Qt)
- 로직·GUI 완전 분리(`engine`/`embed`/`crypto`/`analysis` ↔ `qt`). 다크테마 QSS, QThread 비동기(프리징 해결).
- tkinter 버전은 `run_tk.py`/`app.py`로 보존.

### 초기 개편 (단일 파일 → 패키지)
- 2,269줄 단일 `steg_studio.py`를 `steg_studio/` 패키지로 분리. 원본은 `backup/`에 보존.
- **버그 수정**: PDF 구조 내부(`/JS`) 은닉 코드가 뷰어에 안 뜨던 문제 → 추출·디코딩해 항목으로 노출
  (`hidden_code (1).pdf` 검증: `app.alert('Hello world~');`).

---

## 현재 구조 요약
```
Steganography/
├─ run.py / run_tk.py          # Qt / (레거시) tkinter 실행
├─ sandbox.wsb                 # Windows Sandbox 설정
├─ README / FUNCTIONS / ROADMAP / CHANGELOG
├─ requirements.txt
├─ steg_studio/
│  ├─ constants · crypto · analysis · embed · engine   # 코어(UI 비의존)
│  ├─ steganalysis · docscan                            # 탐지 확장(UI 비의존)
│  ├─ sandbox · sandbox_runner                          # 프로세스 격리
│  ├─ cli · __main__                                    # CLI
│  ├─ app.py                                            # 레거시 tkinter GUI
│  └─ qt/ (main_window · scan_tab · embed_tab · batch_tab · settings_tab
│          · entropy_chart · workers · theme · config · engine_flags)
└─ backup/steg_studio.py       # 원본 단일 파일
```

## 다음 후보
- B: IOC 추출(URL/IP/도메인/해시) · 일괄 스캔 리포트(CSV/HTML) · 파일 비교(diff)
- 상용화 1단계: pytest 단위 테스트 + GitHub Actions CI
- 보안 C8: 암호화/서명 키 분리(HKDF) + PBKDF2 상향(새 버전 플래그로 하위호환)
