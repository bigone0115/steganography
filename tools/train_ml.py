"""
SPAM686 + SCA-Residual(1372차원) 2-Head(LSBM / HILL) 스테그분석 분류기 학습 및 FPR 임계값 자동 보정.

사용: python tools/train_ml.py <BOSSbase .pgm 폴더> [--n 2000] [--workers 8]
- 이미지 단위로 학습(70%)/검증(15%)/테스트(15%) 분할(누수 방지)
- 은닉본: LSBM(0.1/0.2/0.4 bpp), HILL(0.2/0.4 bpp) 시뮬레이션
- 각 헤드(lsbm, hill)별로 검증셋 커버 FPR 기준 Recall@FPR2.5%가 가장 높은 분류기를 선택하고,
  2-Head 결합 오탐률이 MEDIUM(0.75)≈2.5%, HIGH(0.90)≈0.5%가 되도록 분위수 임계값을 보정해 저장.
- 결과: steg_studio/models/spam_clf.joblib + 테스트 탐지율/오탐률 리포트(models/spam_report.txt)
"""
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

VARIANTS = [("cover", 0), ("lsbm", 0.1), ("lsbm", 0.2), ("lsbm", 0.4), ("hill", 0.2), ("hill", 0.4)]
FEATURE_MODE = "spam686_sca1372"
FEAT_DIM = 1372


def _features(args):
    idx, path = args
    rng = np.random.default_rng(idx)
    g = np.asarray(Image.open(path).convert("L"))
    out = []
    for kind, pay in VARIANTS:
        if kind == "cover":
            x = g
        elif kind == "lsbm":
            x = ml.simulate_lsbm(g, pay, rng)
        else:
            x = ml.simulate_hill(g, pay, rng)
        out.append(ml.extract_features(x, mode=FEATURE_MODE))
    return idx, np.stack(out)


def _recall_at_fpr(clf, X_cov, X_pos, target_fpr=0.025):
    """검증셋 커버의 (1 - target_fpr) 분위수를 임계값으로 삼았을 때 양성 샘플의 탐지율(Recall)을 반환."""
    p_cov = clf.predict_proba(X_cov)[:, 1]
    p_pos = clf.predict_proba(X_pos)[:, 1]
    thr = float(np.quantile(p_cov, 1.0 - target_fpr))
    return float((p_pos >= thr).mean()), thr


def main():
    # Windows 기본 콘솔(cp949)은 리포트의 '≈' 등 유니코드를 못 찍어 맨 끝에서 크래시 → utf-8로 재설정
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    a = ap.parse_args()

    files = sorted(glob.glob(os.path.join(a.folder, "**", "*.pgm"), recursive=True))
    if not files:
        sys.exit(f"pgm 파일이 없습니다: {a.folder}")
    rng = np.random.default_rng(42)
    files = [files[i] for i in rng.permutation(len(files))[:a.n]]
    print(f"[*] 이미지 {len(files)}장, 워커 {a.workers}개로 {FEAT_DIM}차원 특징 추출…", flush=True)

    t0 = time.time()
    feats = np.zeros((len(files), len(VARIANTS), FEAT_DIM), dtype=np.float64)
    with Pool(a.workers) as pool:
        for k, (idx, f) in enumerate(pool.imap_unordered(_features, enumerate(files), chunksize=4), 1):
            feats[idx] = f
            if k % 100 == 0:
                print(f"    {k}/{len(files)} ({time.time() - t0:.0f}s)", flush=True)

    n = len(files)
    tr, va = int(n * 0.70), int(n * 0.85)
    split = {"train": range(0, tr), "val": range(tr, va), "test": range(va, n)}

    def xy(rows, pos_variants):
        X, y = [], []
        for i in rows:
            X.append(feats[i, 0])
            y.append(0)
            for v in pos_variants:
                X.append(feats[i, v])
                y.append(1)
        return np.array(X), np.array(y)

    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import HistGradientBoostingClassifier

    head_specs = {
        "lsbm": [1, 2, 3],   # LSBM 0.1, 0.2, 0.4 bpp
        "hill": [4, 5],      # HILL 0.2, 0.4 bpp
    }

    def make_candidates():
        return {
            "logreg_c1": make_pipeline(StandardScaler(), LogisticRegression(C=1.0, max_iter=3000, class_weight="balanced")),
            "logreg_c02": make_pipeline(StandardScaler(), LogisticRegression(C=0.2, max_iter=3000, class_weight="balanced")),
            "logreg_c5": make_pipeline(StandardScaler(), LogisticRegression(C=5.0, max_iter=3000, class_weight="balanced")),
            "hgb": HistGradientBoostingClassifier(max_iter=350, learning_rate=0.06, max_leaf_nodes=31, min_samples_leaf=20, l2_regularization=1.0, class_weight="balanced", random_state=42),
        }

    Xva_cov = feats[list(split["val"]), 0]
    heads = {}
    chosen_names = {}

    for hname, pos_vars in head_specs.items():
        Xtr, ytr = xy(split["train"], pos_vars)
        Xva_pos = np.concatenate([feats[list(split["val"]), v] for v in pos_vars], axis=0)
        best_clf, best_cname, best_rec = None, "", -1.0
        for cname, clf in make_candidates().items():
            clf.fit(Xtr, ytr)
            # 2-Head 결합 시 FPR≈2.5%를 맞추기 위해 개별 헤드는 FPR=1.5% 기준 Recall로 평가
            rec, _ = _recall_at_fpr(clf, Xva_cov, Xva_pos, target_fpr=0.015)
            print(f"[*] [{hname.upper()}] 검증 Recall@FPR1.5% ({cname}): {rec:.3f}", flush=True)
            if rec > best_rec:
                best_clf, best_cname, best_rec = clf, cname, rec

        # Val 커버에서 임계값(thr_med, thr_high) 보정 후, train 데이터로 학습된 모델 또는 train+val 재학습
        # 주의: train+val로 재학습하면 val 커버가 학습에 포함되어 분위수가 과적합되므로,
        # 분류기는 train(70%)으로 학습된 best_clf의 val(15%) 커버 분포로 정직한(held-out) 분위수를 먼저 구하거나,
        # Cross-val out-of-fold 예측으로 임계값을 보정한다. 여기서는 held-out val(15%) 분위수로 엄격히 보정!
        p_val_cov = best_clf.predict_proba(Xva_cov)[:, 1]
        # 2개 헤드 결합(max) 시 목표 FPR 2.5% / 0.5%를 달성하기 위한 헤드별 분위수(Šidák 보정 근사: 98.5% / 99.75%)
        thr_med = float(np.quantile(p_val_cov, 0.985))
        thr_high = float(np.quantile(p_val_cov, 0.9975))
        heads[hname] = {"clf": best_clf, "thr_med": thr_med, "thr_high": thr_high, "model_name": best_cname}
        chosen_names[hname] = best_cname
        print(f"    -> [{hname.upper()}] 선택: {best_cname} | thr_med={thr_med:.4f}, thr_high={thr_high:.4f}", flush=True)

    # 테스트셋(15%) 평가: 단일 헤드 & 2-Head 결합 보정 확률(0.75 MEDIUM / 0.90 HIGH)
    test_rows = list(split["test"])
    header = (f"SPAM686+SCA1372 2-Head(LSBM={chosen_names['lsbm']}, HILL={chosen_names['hill']}) | "
              f"학습 {tr}장, 임계보정 {va - tr}장, 테스트 {n - va}장")
    lines = [header]

    def eval_calibrated(X_batch):
        cals = []
        for hname in ("lsbm", "hill"):
            h = heads[hname]
            raws = h["clf"].predict_proba(X_batch)[:, 1]
            cals.append([ml._calibrate_prob(r, h["thr_med"], h["thr_high"]) for r in raws])
        return np.maximum(cals[0], cals[1])

    for thr_val, thr_name in [(0.75, "0.75(MEDIUM, 목표FPR≈2.5%)"), (0.90, "0.90(HIGH, 목표FPR≈0.5%)")]:
        lines.append(f"\n[임계값 {thr_name}]")
        for v, (kind, pay) in enumerate(VARIANTS):
            Xv = feats[test_rows, v]
            cal_p = eval_calibrated(Xv)
            rate = float((cal_p >= thr_val).mean())
            label = "오탐률(커버를 은닉으로 판정)" if kind == "cover" else f"탐지율 {kind.upper()} {pay} bpp"
            lines.append(f"  {label}: {rate:.1%}")

    report = "\n".join(lines)
    print("\n" + report, flush=True)

    import joblib
    os.makedirs(os.path.dirname(ml.MODEL_PATH), exist_ok=True)
    payload = {
        "schema": "v2_dual_head",
        "feature_mode": FEATURE_MODE,
        "heads": heads,
        "clf": heads["lsbm"]["clf"],   # 레거시 단일 키 폴백
        "info": header,
    }
    joblib.dump(payload, ml.MODEL_PATH)
    with open(os.path.join(os.path.dirname(ml.MODEL_PATH), "spam_report.txt"), "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"[+] 모델 저장: {ml.MODEL_PATH} ({time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()
