"""
JPEG 전용 스테그분석 분류기 학습 — DCTR 8000차원 + 로지스틱 회귀, 품질계수(QF)별 모델.

사용: python tools/train_jpeg.py <BOSSbase .pgm 폴더> [--n 2000] [--qfs 75,90] [--workers 8]
- 커버: pgm을 Pillow로 QF별 JPEG 압축 → 우리 디코더로 양자화 DCT 계수 추출(추론 경로와 동일)
- 은닉본(메모리상 계수만, 파일 미생성): nsF5 0.1 / UERD 0.2·0.4 / J-UNIWARD 0.2·0.4 bpnzAC 랜덤 페이로드
- 이미지 단위 학습 70% / 임계보정 15% / 테스트 15% 분할(누수 방지)
- 보정 커버 FPR 2.5%(MEDIUM=0.75) / 0.5%(HIGH=0.90) 분위수로 임계값 저장
- 결과: steg_studio/models/jpeg_clf.joblib + models/jpeg_report.txt
"""
import io
import os
import sys
import glob
import time
import argparse
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import numpy as np
from PIL import Image
from steg_studio import ml

VARIANTS = [("cover", 0), ("nsf5", 0.1), ("uerd", 0.2), ("uerd", 0.4), ("juniward", 0.2), ("juniward", 0.4)]


def _features(args):
    """(이미지 번호, 경로, QF) → (번호, 변형별 DCTR 특징 [len(VARIANTS) x 8000])."""
    idx, path, qf = args
    rng = np.random.default_rng((idx, qf))
    buf = io.BytesIO()
    Image.open(path).convert("L").save(buf, "JPEG", quality=qf)
    coef, q = ml.jpeg_luma(buf.getvalue())
    out = []
    for kind, pay in VARIANTS:
        c = coef if kind == "cover" else ml.JPEG_SIMULATORS[kind](coef, q, pay, rng)
        out.append(ml.dctr_features(c, q, qf))
    return idx, np.stack(out)


def train_qf(files, qf, workers, lines):
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import LogisticRegression

    t0 = time.time()
    n = len(files)
    feats = np.zeros((n, len(VARIANTS), 8000), dtype=np.float32)
    with Pool(workers) as pool:
        for k, (idx, f) in enumerate(pool.imap_unordered(_features, [(i, p, qf) for i, p in enumerate(files)], chunksize=2), 1):
            feats[idx] = f
            if k % 100 == 0:
                print(f"    QF{qf}: {k}/{n} ({time.time() - t0:.0f}s)", flush=True)

    tr, va = int(n * 0.70), int(n * 0.85)
    X_tr = feats[:tr].reshape(-1, 8000)
    y_tr = np.tile([0] + [1] * (len(VARIANTS) - 1), tr)
    X_va_cov = feats[tr:va, 0]
    X_va_pos = feats[tr:va, 1:].reshape(-1, 8000)

    # ponytail: 로지스틱 회귀 C 2개만 비교. 적응형(J-UNIWARD) 탐지율이 부족하면 FLD 앙상블(Kodovský 2012)로 교체
    best = None
    for C in (0.1, 1.0):
        clf = make_pipeline(StandardScaler(), LogisticRegression(C=C, max_iter=3000, class_weight="balanced"))
        clf.fit(X_tr, y_tr)
        thr = float(np.quantile(clf.predict_proba(X_va_cov)[:, 1], 0.975))
        rec = float((clf.predict_proba(X_va_pos)[:, 1] >= thr).mean())
        print(f"[*] QF{qf} 검증 Recall@FPR2.5% (C={C}): {rec:.3f}", flush=True)
        if best is None or rec > best[0]:
            best = (rec, C, clf)
    _, C, clf = best
    p_cov = clf.predict_proba(X_va_cov)[:, 1]
    model = {"clf": clf, "thr_med": float(np.quantile(p_cov, 0.975)), "thr_high": float(np.quantile(p_cov, 0.995))}

    lines.append(f"\n== QF{qf} (logreg C={C}) | 학습 {tr}장, 임계보정 {va - tr}장, 테스트 {n - va}장 ==")
    for thr_val, name in [(0.75, "MEDIUM ≥0.75"), (0.90, "HIGH ≥0.90")]:
        row = []
        for v, (kind, pay) in enumerate(VARIANTS):
            raws = clf.predict_proba(feats[va:, v])[:, 1]
            rate = np.mean([ml._calibrate_prob(r, model["thr_med"], model["thr_high"]) >= thr_val for r in raws])
            row.append(f"{'오탐률' if kind == 'cover' else f'{kind} {pay}'} {rate:.1%}")
        lines.append(f"  [{name}] " + " | ".join(row))
    print(f"    QF{qf} 완료 ({time.time() - t0:.0f}s)", flush=True)
    return model


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # cp949 콘솔 크래시 방지
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--qfs", default="75,90")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    a = ap.parse_args()

    files = sorted(glob.glob(os.path.join(a.folder, "**", "*.pgm"), recursive=True))
    if not files:
        sys.exit(f"pgm 파일이 없습니다: {a.folder}")
    files = [files[i] for i in np.random.default_rng(42).permutation(len(files))[:a.n]]
    qfs = [int(s) for s in a.qfs.split(",")]
    print(f"[*] 이미지 {len(files)}장 x QF {qfs}, 워커 {a.workers}개", flush=True)

    lines = ["DCTR8000 + logreg, 은닉본: " + ", ".join(f"{k} {p}" for k, p in VARIANTS[1:]) + " bpnzAC (BOSSbase 512px 흑백)"]
    models = {qf: train_qf(files, qf, a.workers, lines) for qf in qfs}
    report = "\n".join(lines)
    print("\n" + report, flush=True)

    import joblib
    info = f"DCTR8000 logreg, BOSSbase {len(files)}장, QF {qfs}"
    joblib.dump({"schema": "jpeg_v1", "models": models, "info": info}, ml.JPEG_MODEL_PATH)
    with open(os.path.join(os.path.dirname(ml.JPEG_MODEL_PATH), "jpeg_report.txt"), "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"[+] 모델 저장: {ml.JPEG_MODEL_PATH}")


if __name__ == "__main__":
    main()
