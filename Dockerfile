# Stego & Forensic Security Studio — CLI 컨테이너 (GUI 제외: 화면 없는 컨테이너에선 PySide6 불필요)
# 빌드:  docker build -t steg-studio .
# 사용:  docker run --rm -v "<분석할 폴더>:/data" steg-studio scan /data/<파일>
FROM python:3.12-slim

WORKDIR /app
# requirements.txt에서 GUI(PySide6)만 빼고 설치 — 나머지는 선택 의존성이라 실패해도 해당 기능만 꺼짐
COPY requirements.txt .
RUN grep -v -i "^PySide6" requirements.txt | sed 's/#.*//' | xargs pip install --no-cache-dir

COPY steg_studio ./steg_studio
COPY tools ./tools

# 분석 대상은 볼륨으로 /data에 마운트. 루트 아닌 사용자로 실행(의심 파일을 다루는 도구라서)
RUN useradd -m analyst
USER analyst
WORKDIR /data
ENV PYTHONIOENCODING=utf-8 PYTHONPATH=/app
ENTRYPOINT ["python", "-m", "steg_studio"]
CMD ["--help"]
