"""
학습된 모델의 임계값별 오탐률/탐지율 평가 (train_ml.py와 같은 분할의 테스트 20%).
사용: python tools/eval_ml.py <BOSSbase .pgm 폴더> [--n 2000]
"""
import os
import sys
import glob
import argparse
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
import joblib
from steg_studio import ml
from tools.train_ml import _features, VARIANTS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    a = ap.parse_args()
    files = sorted(glob.glob(os.path.join(a.folder, "**", "*.pgm"), recursive=True))
    files = [files[i] for i in np.random.default_rng(42).permutation(len(files))[:a.n]]
    test = list(enumerate(files))[int(len(files) * 0.8):]
    with Pool(a.workers) as pool:
        feats = dict(pool.imap_unordered(_features, test, chunksize=4))
    clf = joblib.load(ml.MODEL_PATH)["clf"]
    probs = {v: clf.predict_proba(np.stack([feats[i][v] for i in feats]))[:, 1] for v in range(len(VARIANTS))}
    print("임계값 | 오탐률 | " + " | ".join(f"{k.upper()} {p}" for k, p in VARIANTS[1:]))
    for thr in (0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95):
        row = [f"{(probs[v] >= thr).mean():6.1%}" for v in range(len(VARIANTS))]
        print(f" {thr:.2f}  | " + " | ".join(row))


if __name__ == "__main__":
    main()
