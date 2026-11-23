"""
탐지기 학습·평가용 라벨 스테가 코퍼스 생성기 (방어 스코프 가드레일 B).

표준 공개 알고리즘(LSBM/HILL/WOW/S-UNIWARD)으로 커버 이미지에 **랜덤 페이로드**를 매립해
cover(라벨 0) / stego(라벨 1) 코퍼스를 디스크에 생성한다. 목적은 "내 탐지기가 이 은닉을 잡나" 측정.
※ 회피 최적화·실제 악성 페이로드 은닉·배포용 숨기기 기능이 아니다(steganography-defensive-scope).

사용: python tools/make_corpus.py <커버폴더> <출력폴더> [--algos hill,wow,suniward,lsbm] [--bpp 0.4] [--n 200]
출력: <출력폴더>/cover/*.png, <출력폴더>/<algo>_<bpp>/*.png, manifest.csv(파일,라벨,알고리즘,bpp,원본)
"""
import os
import sys
import csv
import glob
import argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import numpy as np
from PIL import Image
from steg_studio import ml

EXTS = ("*.pgm", "*.png", "*.bmp", "*.tif", "*.tiff", "*.jpg", "*.jpeg")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("covers")
    ap.add_argument("out")
    ap.add_argument("--algos", default="hill,wow,suniward,lsbm")
    ap.add_argument("--bpp", type=float, default=0.4)
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    algos = [s.strip() for s in a.algos.split(",") if s.strip()]
    bad = [s for s in algos if s not in ml.SIMULATORS]
    if bad:
        sys.exit(f"알 수 없는 알고리즘: {bad} (가능: {list(ml.SIMULATORS)})")

    files = []
    for ext in EXTS:
        files += glob.glob(os.path.join(a.covers, "**", ext), recursive=True)
    files = sorted(set(files))
    if not files:
        sys.exit(f"커버 이미지가 없습니다: {a.covers}")
    rng = np.random.default_rng(a.seed)
    files = [files[i] for i in rng.permutation(len(files))[:a.n]]

    os.makedirs(os.path.join(a.out, "cover"), exist_ok=True)
    for alg in algos:
        os.makedirs(os.path.join(a.out, f"{alg}_{a.bpp}"), exist_ok=True)

    rows = []
    for idx, src in enumerate(files):
        g = np.asarray(Image.open(src).convert("L"))
        stem = f"{idx:05d}"
        cov_path = os.path.join("cover", stem + ".png")
        Image.fromarray(g).save(os.path.join(a.out, cov_path))
        rows.append((cov_path, 0, "cover", 0.0, os.path.basename(src)))
        for alg in algos:
            # 알고리즘·이미지별 독립 시드 → 재현 가능한 랜덤 페이로드 매립
            y = ml.SIMULATORS[alg](g, a.bpp, np.random.default_rng((a.seed, idx, alg).__hash__() & 0xFFFFFFFF))
            rel = os.path.join(f"{alg}_{a.bpp}", stem + ".png")
            Image.fromarray(y).save(os.path.join(a.out, rel))
            rows.append((rel, 1, alg, a.bpp, os.path.basename(src)))
        if (idx + 1) % 50 == 0:
            print(f"    {idx + 1}/{len(files)}", flush=True)

    with open(os.path.join(a.out, "manifest.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file", "label", "algo", "bpp", "source"])
        w.writerows(rows)

    n_cov = sum(1 for r in rows if r[1] == 0)
    n_steg = len(rows) - n_cov
    print(f"[+] 코퍼스 생성: cover {n_cov} / stego {n_steg} ({', '.join(algos)} @ {a.bpp}bpp) → {a.out}")
    print(f"    manifest.csv (라벨 0=cover, 1=stego) 로 탐지율/오탐률 평가")


if __name__ == "__main__":
    main()
