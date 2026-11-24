# Stego & Forensic Security Studio (v5)

이미지·오디오·문서 파일에 데이터를 **은닉(스테가노그래피)** 하고, 숨겨진 데이터를
**탐지·추출·분석**하는 방어 지향 포렌식 도구입니다. 기본 GUI는 Qt(PySide6)이며,
tkinter 버전도 레거시 실행 진입점으로 제공합니다.

## 실행

```bash
pip install -r requirements.txt   # 최초 1회
python run.py                     # Qt(PySide6) GUI
python run_tk.py                  # (레거시) tkinter GUI
```

### CLI (GUI 없이 터미널/서버/자동화)

```bash
python -m steg_studio scan  악성.pdf --isolated --json report.json
python -m steg_studio embed carrier.png payload.py -o out.png --password pw
python -m steg_studio sanitize 의심.png -o 안전본.png
python -m steg_studio batch 폴더 -r --csv out.csv --html out.html
python -m steg_studio diff 원본.png 의심.png
```

### Docker (웹 UI / CLI)

설치 없이 이미지를 받아 실행합니다. 이미지는 GitHub Actions(`.github/workflows/docker.yml`)가
테스트 통과 후 GHCR에 자동 배포합니다 — `main` 푸시 시 `:main`, `v*` 태그 시 `:<버전>`·`:latest`.

```bash
docker pull ghcr.io/bigone0115/steganography:main

# 웹 UI → 브라우저에서 http://localhost:47821
docker run --rm -p 127.0.0.1:47821:47821 ghcr.io/bigone0115/steganography:main web --host 0.0.0.0

# CLI (현재 폴더를 /data로 연결)
docker run --rm -v "$PWD:/data" ghcr.io/bigone0115/steganography:main scan /data/의심.png
```

직접 빌드: `docker build -t steg-studio .` · 컨테이너에는 데스크톱 GUI(PySide6)가 없고, 웹 UI에는 은닉 탭을 두지 않습니다.

### 플랫폼

Windows·Linux·macOS 공통으로 동작합니다(코드는 하나로 유지). 프로세스 격리는
Windows=Job Object, Linux/macOS=setrlimit(+firejail 있으면 추가)로 자동 분기합니다.
Windows Sandbox(`sandbox.wsb`)는 Windows 전용이며, 리눅스에선 Docker/firejail로 대체하세요.

> 함수별 상세 설명은 **[FUNCTIONS.md](FUNCTIONS.md)** 참고.

| 패키지 | 역할 / 없을 때 |
|--------|----------------|
| PySide6 | Qt GUI(run.py) 필수. 없으면 run_tk.py(tkinter)로 실행 |
| Pillow | 이미지 LSB 은닉/렌더링·미리보기. 없으면 해당 기능만 비활성 |
| yara-python | YARA 룰 탐지. 없으면 내장 정규식으로 자동 폴백 |
| olefile | HWP 5.x·DOC·XLS·PPT(OLE 복합문서) 내부 구조 분석 |
| oletools | VBA 매크로 추출 및 자동실행/의심 키워드 탐지 |
| numpy, scikit-learn | ML 스테그분석(SPAM 특징 + 분류기, ±1 matching/적응형 은닉). 없으면 ML만 비활성 |
| imageio-ffmpeg | 영상 코덱 판별·무손실 키프레임 추출. 없으면 영상 프레임 분석만 비활성 |

## 폴더 구조

```
Steganography/
├─ run.py                 # Qt 실행 진입점
├─ run_tk.py              # 레거시 tkinter 진입점
├─ requirements.txt
├─ README.md
├─ steg_studio/           # 패키지
│  ├─ __init__.py
│  ├─ constants.py        # 매직 시그니처, 패킷 플래그, 메모리 보호 상한선
│  ├─ crypto.py           # 패킷 직렬화·암호화·파싱 (UI 비의존 순수 함수)
│  ├─ analysis.py         # 엔트로피·포맷 식별·Hex 덤프 (UI 비의존 순수 함수)
│  ├─ embed.py            # 은닉 생성 로직 (UI 비의존)
│  ├─ engine.py           # 포렌식 스캔 엔진 (UI 비의존) → ScanResult 반환
│  ├─ steganalysis.py     # 통계 스테그분석: 카이제곱·RS·WS·HCF·다중순서LSB·JPEG(JSteg/F5)·오디오·텍스트
│  ├─ container.py        # PNG IDAT / MP4 박스 틈새 검사
│  ├─ ioc.py              # IOC 추출(URL/IP/도메인/이메일/해시)
│  ├─ ml.py               # SPAM686 + 분류기 (models/spam_clf.joblib)
│  ├─ video.py            # ffmpeg 코덱 판별·무손실 키프레임 추출
│  ├─ docscan.py / sandbox.py / cli.py
│  ├─ app.py              # 레거시 tkinter GUI (StegForensicStudioV5)
│  └─ qt/                 # Qt(PySide6) GUI
│     ├─ main_window.py   # 3탭 조립 + 다크 테마
│     ├─ theme.py         # QSS 다크 테마
│     ├─ workers.py       # QThread (스캔/VT/일괄) — UI 프리징 방지
│     ├─ entropy_chart.py # 구간별 엔트로피 차트 (QPainter)
│     ├─ scan_tab.py      # 스캐너 (목록/로그/코드·이미지·비트평면·엔트로피·메타 + CDR)
│     ├─ embed_tab.py / batch_tab.py
│     └─ engine_flags.py
├─ tests/test_detectors.py  # 탐지기 회귀 테스트
├─ tools/train_ml.py · eval_ml.py  # ML 학습·평가
└─ backup/                # 원본 단일 파일 + 직전 패키지 백업
```

## 설계 메모

- **로직·GUI 완전 분리**: 모든 스캔/은닉/암호화 로직은 `engine`·`embed`·`crypto`·`analysis`
  모듈에 UI 없이 들어 있고, Qt/tkinter GUI는 이를 호출만 합니다.
  `engine.scan_file(path)` 하나로 CLI·웹·테스트 어디서든 재사용됩니다.
- **반응성**: Qt 버전은 스캔·VirusTotal·일괄 작업을 QThread로 돌려 UI가 멈추지 않습니다.
- **안전장치**: 압축 폭탄 방어(32MB 상한), 파일 로드 상한(256MB),
  HMAC `compare_digest` 상수시간 비교, 분석 대상 파일 비실행 원칙.

## 기능 요약

1. **은닉**: 이미지 LSB / WAV 오디오 LSB / EOF 암호화 패킷 결합 / Raw 결합(polyglot)
2. **포렌식 스캔**: EOF 카빙, LSB·메타데이터 검사, base64/URL 난독화 해제,
   YARA·정규식 패턴 탐지, 엔트로피/비트평면 시각화, VirusTotal 해시 조회, CDR 무해화
   - 구조 내부 코드 노출: PDF `/JS`·`/OpenAction`·`/Launch`·`/EmbeddedFile` + PNG/JPEG/MP3 메타데이터 코드
   - 문서형 분석: **HWP 5.x·DOC·XLS·PPT(OLE)**, **HWPX·DOCX·XLSX·PPTX(ZIP)**, **VBA 매크로**(자동실행/의심 키워드), HWP BinData zlib 해제 후 재검사
   - **통계적 스테그분석**: 카이제곱(순차), RS(무작위·은닉률), WS+띠별(소량·국소), HCF-COM(±1, 참고), zsteg식 다중 순서 LSB
   - **JPEG**: 순수 Python 디코더(baseline+progressive)로 JSteg·F5 탐지
   - **ML 스테그분석**: SPAM686 + 로지스틱 회귀 — ±1 matching 실용 수준, 적응형(HILL)은 약함(오탐 2.5% 기준 LSBM 0.4bpp 86%, HILL 0.4bpp 20%)
   - **오디오**: 에코 은닉, 위상 코딩 · **텍스트**: 제로폭 문자, SNOW 공백, 동형 문자 · **영상**: 무손실 코덱 키프레임
   - **컨테이너 틈새**: PNG IDAT(zlib 뒤 잔여/초과 해제/필터 바이트), MP4(미참조 mdat, free/skip)
   - **IOC 추출**: URL/IP/도메인/이메일/해시 → 리포트 포함
   - **사용자 YARA 룰 로딩**(설정에서 `.yar` 폴더 지정) · **재귀 추출**(중첩 은닉: PNG 속 ZIP 속 문서까지)
   - 다중 해시(MD5/SHA-1/SHA-256) 복사, 문자열(strings) 추출, 드래그&드롭 스캔
   - HTML/JSON 리포트 내보내기
3. **일괄 스캔**: 폴더 단위 빠른 점검 (결과 더블클릭 → 스캐너 탭에서 열기), CSV/HTML 리포트 저장
4. **설정(⚙)**: 다크/화이트 테마, VirusTotal 키 저장, 기본 격리/제한시간/메모리상한,
   strings 최소 길이, 기본 저장 폴더 — OS 표준 위치에 영구 저장(QSettings)

> 분석 대상 파일은 **절대 실행하지 않습니다.** 탐지는 바이트 패턴·구조 분석으로만 수행합니다.

## 격리(Sandbox) — 악성 검체 분석 시 안전장치

이 도구는 파일을 실행하지 않으므로 주요 위험은 (1) 파서 라이브러리(Pillow/zlib 등)
취약점과 (2) 자원 고갈입니다. 두 층위의 격리를 제공합니다.

1. **프로세스 격리 (상시, 기본 ON)** — 스캐너 탭의 "샌드박스(프로세스 격리) 스캔" 체크박스.
   스캔을 별도 자식 프로세스(`sandbox_runner`)에서 실행합니다. 파서가 크래시·폭주해도
   GUI 본체는 안전하며, Windows Job Object로 **메모리 상한 + 프로세스 종료 시 강제 정리**,
   **시간 상한**을 적용합니다. 스캔 경로는 네트워크를 쓰지 않습니다.
   (같은 OS 계정에서 도는 크래시/DoS 방어 계층이며, 완전한 보안 경계는 아닙니다.)

2. **Windows Sandbox (확실한 악성 검체용 진짜 경계)** — `sandbox.cmd` 더블클릭 (HostFolder를 현재 폴더 경로로 자동 갱신 후 `sandbox.wsb` 실행).
   앱을 네트워크 차단·폴더 읽기전용의 일회용 격리 VM에서 띄웁니다. 창을 닫으면 통째로 폐기됩니다.
   (Windows 11 Pro의 "Windows Sandbox" 기능 활성화 필요. 파일 내 주석에 사용법 명시.)
