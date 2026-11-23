"""
영상 프레임 분석 — ffmpeg(imageio-ffmpeg 번들)로 코덱을 판별하고, 무손실 코덱이면 키프레임을 추출.

손실 코덱(H.264/HEVC/VP9 등)은 압축 과정에서 픽셀 LSB가 보존되지 않아 프레임 LSB 은닉이
사실상 불가능하므로 분석하지 않는다(정직한 범위 제한). 컨테이너 틈새는 container.py가 담당.
ffmpeg는 신뢰할 수 없는 입력을 파싱하므로 별도 프로세스 + 타임아웃으로만 실행한다.
"""

import os
import re
import glob
import shutil
import tempfile
import subprocess

LOSSLESS_CODECS = {"ffv1", "huffyuv", "ffvhuff", "png", "rawvideo", "utvideo", "magicyuv",
                   "qtrle", "r210", "v210", "v308", "v408", "v410", "zlib", "lagarith", "apng", "bmp"}


def ffmpeg_exe():
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:
        return shutil.which("ffmpeg")


def probe_codec(path, timeout=30):
    """비디오 스트림 코덱 이름(소문자) 또는 None."""
    exe = ffmpeg_exe()
    if not exe:
        return None
    try:
        p = subprocess.run([exe, "-hide_banner", "-i", path], capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    m = re.search(r"Video:\s*([A-Za-z0-9_]+)", p.stderr.decode("utf-8", "replace"))
    return m.group(1).lower() if m else None


def extract_keyframes(path, max_frames=4, timeout=120):
    """키프레임(I-frame)을 PNG로 추출해 (임시폴더, [파일경로]) 반환. 호출자가 폴더를 지운다."""
    exe = ffmpeg_exe()
    out = tempfile.mkdtemp(prefix="steg_frames_")
    cmd = [exe, "-hide_banner", "-v", "error", "-i", path,
           "-vf", "select='eq(pict_type,I)'", "-fps_mode", "vfr", "-frames:v", str(max_frames),
           os.path.join(out, "f_%02d.png")]
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return out, sorted(glob.glob(os.path.join(out, "f_*.png")))
