"""
머신러닝 스테그분석 — SPAM686 + 선택채널(질감) 가중 고차 잔차(SCA-Residual) 1372차원 + 2-Head 분류기.

통계 검정(카이제곱/RS/WS)이 못 잡는 ±1 LSB matching, HILL·S-UNIWARD 계열 '적응형' 은닉을
학습 기반으로 탐지한다. numpy/scikit-learn/모델 파일이 없으면 available()=False로 조용히 비활성.

- spam_features(gray): Pevný 2010 SPAM, 2차 마르코프, T=3 → 2 x 343 = 686차원 (하위 호환 유지)
- sca_residual_features(gray): 질감 선택채널 가중 1차 차분 + 2차 라플라시안/KB 고주파 잔차 마르코프 → 686차원
- extract_features(gray): SPAM686 + SCA-Residual = 1372차원
- simulate_lsbm / simulate_hill / simulate_wow / simulate_suniward: 탐지기 학습·평가용 라벨 코퍼스 전용 표준 은닉 시뮬레이터(랜덤 페이로드만, 회피 최적화·실페이로드 은닉 아님)
- predict(img): (보정 은닉 확률 0~1, 설명) 또는 None (0.75=MEDIUM/FPR≈2.5%, 0.90=HIGH/FPR≈0.5%)
모델 학습: python tools/train_ml.py <BOSSbase 폴더>
"""

import os

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "spam_clf.joblib")
T = 3

try:
    import numpy as np
    NUMPY_OK = True
except ImportError:
    NUMPY_OK = False

_model = None


def available():
    return NUMPY_OK and os.path.isfile(MODEL_PATH)


# =========================================================================
# SPAM686 및 선택채널(질감) 가중 고차 잔차(SCA-Residual) 특징
# =========================================================================
def _markov(d1, d2, d3, w=None):
    """잘린 차분 3연속 (d1,d2,d3)의 조건부 확률 P(d3 | d1, d2) → 343차원. w가 있으면 선택채널 가중."""
    k = 2 * T + 1
    a, b, c = (d1 + T).ravel(), (d2 + T).ravel(), (d3 + T).ravel()
    ww = w.ravel() if w is not None else None
    tri = np.bincount((a * k + b) * k + c, weights=ww, minlength=k ** 3).astype(np.float64)
    pair = np.bincount(a * k + b, weights=ww, minlength=k * k).astype(np.float64)
    pair = np.repeat(pair, k)
    return np.divide(tri, pair, out=np.zeros_like(tri), where=pair > 0)


def _box_mean(arr, r):
    """반경 r (커널 (2r+1)x(2r+1)) 2D 균일 평균 필터 — 적분 이미지(cumsum) 기반 순수 NumPy O(N) 구현."""
    k = 2 * r + 1
    p = np.pad(arr.astype(np.float64), r, mode="reflect")
    cs = np.pad(p, ((1, 0), (1, 0))).cumsum(axis=0).cumsum(axis=1)
    return (cs[k:, k:] - cs[:-k, k:] - cs[k:, :-k] + cs[:-k, :-k]) / (k * k)


def _kb_residual(x):
    """3x3 Ker-Böhme (KB) 고주파 잔차 필터 (reflect 패딩, scipy 불필요)."""
    p = np.pad(x.astype(np.int32), 1, mode="reflect")
    return (
        -p[:-2, :-2] + 2 * p[:-2, 1:-1] - p[:-2, 2:]
        + 2 * p[1:-1, :-2] - 4 * p[1:-1, 1:-1] + 2 * p[1:-1, 2:]
        - p[2:, :-2] + 2 * p[2:, 1:-1] - p[2:, 2:]
    )


def _hill_selection_weights(x):
    """
    HILL 비용의 역수(1/rho)에 비례하는 픽셀별 질감 선택채널 가중치 맵.
    평탄 영역(은닉 확률≈0)의 가중치를 낮추고 적응형 은닉이 집중되는 고주파 질감 영역을 강조한다.
    """
    r_abs = np.abs(_kb_residual(x)).astype(np.float64)
    l1 = _box_mean(r_abs, 1)
    rho = _box_mean(1.0 / (l1 + 1e-10), 7)
    w = 1.0 / (rho + 1e-4)
    # 상위 질감 영역 강조(거듭제곱 스케일링 후 평균 1로 정규화)
    med = float(np.median(w))
    w = np.where(w >= med, w * w, w * 0.15)
    mean_w = float(w.mean())
    return (w / mean_w) if mean_w > 0 else np.ones_like(w)


def spam_features(gray):
    """gray: 2D uint8/int 배열 → 686차원 표준 SPAM 특징 벡터."""
    x = gray.astype(np.int32)

    def clip(d):
        return np.clip(d, -T, T)

    h = clip(x[:, :-1] - x[:, 1:])          # →
    v = clip(x[:-1, :] - x[1:, :])          # ↓
    dg = clip(x[:-1, :-1] - x[1:, 1:])      # ↘
    ad = clip(x[1:, :-1] - x[:-1, 1:])      # ↗
    straight = (
        _markov(h[:, :-2], h[:, 1:-1], h[:, 2:]),                 # →
        _markov(-h[:, 2:], -h[:, 1:-1], -h[:, :-2]),              # ←
        _markov(v[:-2, :], v[1:-1, :], v[2:, :]),                 # ↓
        _markov(-v[2:, :], -v[1:-1, :], -v[:-2, :]),              # ↑
    )
    diag = (
        _markov(dg[:-2, :-2], dg[1:-1, 1:-1], dg[2:, 2:]),        # ↘
        _markov(-dg[2:, 2:], -dg[1:-1, 1:-1], -dg[:-2, :-2]),     # ↖
        _markov(ad[2:, :-2], ad[1:-1, 1:-1], ad[:-2, 2:]),        # ↗
        _markov(-ad[:-2, 2:], -ad[1:-1, 1:-1], -ad[2:, :-2]),     # ↙
    )
    return np.concatenate([np.mean(straight, axis=0), np.mean(diag, axis=0)])


def sca_residual_features(gray):
    """
    적응형(HILL) 탐지용 686차원 확장 특징:
    - 전반 343차원: HILL 선택채널 가중(w) 1차 차분 마르코프 전이 (평탄 영역 희석 제거)
    - 후반 343차원: 선택채널 가중 2차 라플라시안(Lh, Lv) 및 양자화 KB 잔차(R_KB/2) 마르코프 전이
    """
    x = gray.astype(np.int32)
    w = _hill_selection_weights(x)

    def clip(d):
        return np.clip(d, -T, T)

    # 1) 선택채널 가중 1차 차분 전이 (수평/수직/대각 평균 → 343차원)
    h = clip(x[:, :-1] - x[:, 1:])
    v = clip(x[:-1, :] - x[1:, :])
    dg = clip(x[:-1, :-1] - x[1:, 1:])
    ad = clip(x[1:, :-1] - x[:-1, 1:])
    wh = w[:, 1:-2]
    wv = w[1:-2, :]
    wd = w[1:-2, 1:-2]
    sca_first = np.mean([
        _markov(h[:, :-2], h[:, 1:-1], h[:, 2:], wh),
        _markov(-h[:, 2:], -h[:, 1:-1], -h[:, :-2], wh),
        _markov(v[:-2, :], v[1:-1, :], v[2:, :], wv),
        _markov(-v[2:, :], -v[1:-1, :], -v[:-2, :], wv),
        _markov(dg[:-2, :-2], dg[1:-1, 1:-1], dg[2:, 2:], wd),
        _markov(-dg[2:, 2:], -dg[1:-1, 1:-1], -dg[:-2, :-2], wd),
        _markov(ad[2:, :-2], ad[1:-1, 1:-1], ad[:-2, 2:], wd),
        _markov(-ad[:-2, 2:], -ad[1:-1, 1:-1], -ad[2:, :-2], wd),
    ], axis=0)

    # 2) 2차 라플라시안(SRM spam12) + 양자화 KB 잔차(SRM spam33, q=2) 선택채널 가중 전이 (→ 343차원)
    lh = clip(x[:, :-2] - 2 * x[:, 1:-1] + x[:, 2:])
    lv = clip(x[:-2, :] - 2 * x[1:-1, :] + x[2:, :])
    kb_q = clip(np.trunc(_kb_residual(x) / 2.0).astype(np.int32))
    wlh = w[:, 2:-2]
    wlv = w[2:-2, :]
    wk_h = w[:, 1:-1]
    wk_v = w[1:-1, :]
    sca_high = np.mean([
        _markov(lh[:, :-2], lh[:, 1:-1], lh[:, 2:], wlh),
        _markov(-lh[:, 2:], -lh[:, 1:-1], -lh[:, :-2], wlh),
        _markov(lv[:-2, :], lv[1:-1, :], lv[2:, :], wlv),
        _markov(-lv[2:, :], -lv[1:-1, :], -lv[:-2, :], wlv),
        _markov(kb_q[:, :-2], kb_q[:, 1:-1], kb_q[:, 2:], wk_h),
        _markov(kb_q[:-2, :], kb_q[1:-1, :], kb_q[2:, :], wk_v),
    ], axis=0)

    return np.concatenate([sca_first, sca_high])


def extract_features(gray, mode="spam686_sca1372"):
    """모델의 feature_mode에 따라 1372차원(SPAM686 + SCA-Residual) 또는 686차원(레거시) 특징 반환."""
    base = spam_features(gray)
    if mode == "spam686":
        return base
    return np.concatenate([base, sca_residual_features(gray)])


# =========================================================================
# 은닉 시뮬레이터 (학습용)
# =========================================================================
def simulate_lsbm(gray, payload, rng):
    """LSB matching: payload(bpp) 비율 위치 중 절반(LSB가 이미 맞는 경우 제외)을 ±1 변경."""
    x = gray.astype(np.int16)
    change = rng.random(x.shape) < payload / 2
    pm = rng.choice((-1, 1), size=x.shape)
    pm[x == 0] = 1
    pm[x == 255] = -1
    return np.clip(x + change * pm, 0, 255).astype(np.uint8)


def _ternary_entropy(p):
    p0 = 1 - 2 * p
    with np.errstate(divide="ignore", invalid="ignore"):
        h = -2 * p * np.log2(np.where(p > 0, p, 1)) - p0 * np.log2(np.where(p0 > 0, p0, 1))
    return h.sum()


def _conv2(x, k):
    """소형 커널 2D 상관(reflect 패딩) — scipy 없이 방향성 웨이블릿 필터 적용용 순수 NumPy."""
    kh, kw = k.shape
    p = np.pad(x.astype(np.float64), ((kh // 2, kh // 2), (kw // 2, kw // 2)), mode="reflect")
    out = np.zeros_like(x, dtype=np.float64)
    for i in range(kh):
        for j in range(kw):
            if k[i, j]:
                out += k[i, j] * p[i:i + x.shape[0], j:j + x.shape[1]]
    return out


# Haar(db1) 방향성 웨이블릿 필터 뱅크 (LH/HL/HH, 각 2x2) — WOW·S-UNIWARD 비용의 방향 잔차용.
_LO = np.array([1.0, 1.0]) / np.sqrt(2.0)
_HI = np.array([-1.0, 1.0]) / np.sqrt(2.0)
_WAVE_DIRS = [
    np.outer(_LO, _HI),   # LH (수평 고주파)
    np.outer(_HI, _LO),   # HL (수직 고주파)
    np.outer(_HI, _HI),   # HH (대각 고주파)
]


def _cost_hill(x):
    """HILL(Li 2014): KB 고주파 잔차의 저역 평활 역수 → 질감 영역 저비용. (scipy 있으면 사용, 없으면 적분이미지 폴백)"""
    try:
        from scipy.ndimage import convolve, uniform_filter
        kb = np.array([[-1, 2, -1], [2, -4, 2], [-1, 2, -1]], dtype=np.float64)
        r = np.abs(convolve(x, kb, mode="reflect"))
        l1 = uniform_filter(r, 3, mode="reflect")
        rho = uniform_filter(1.0 / (l1 + 1e-10), 15, mode="reflect")
    except ImportError:
        r = np.abs(_kb_residual(x)).astype(np.float64)
        l1 = _box_mean(r, 1)
        rho = _box_mean(1.0 / (l1 + 1e-10), 7)
    return np.minimum(rho, 1e10)


def _cost_wow(x):
    """WOW(Holub 2012) 계열: 방향 웨이블릿 적합도 ξ_k(큰 값=질감)의 역수 합 → 평탄=고비용, 질감=저비용으로 은닉 집중."""
    acc = np.zeros_like(x, dtype=np.float64)
    for k in _WAVE_DIRS:
        r = _conv2(x, k)                                 # 방향 잔차
        xi = _conv2(np.abs(r), np.abs(k[::-1, ::-1]))    # 미러 필터로 적합도 평활(큰 값=질감)
        acc += 1.0 / (xi + 1e-10)                        # 역수=비용(평탄→∞)
    return np.minimum(acc, 1e10)


def _cost_suniward(x, sigma=1.0):
    """S-UNIWARD(Holub 2014): 방향 웨이블릿 부대역 상대변화의 가법 근사 비용 ρ=Σ_k(1/(σ+|W_k|) ⊛ |K_k|)."""
    rho = np.zeros_like(x, dtype=np.float64)
    for k in _WAVE_DIRS:
        w = _conv2(x, k)
        rho += _conv2(1.0 / (np.abs(w) + sigma), np.abs(k[::-1, ::-1]))
    return np.minimum(rho, 1e10)


def _embed_adaptive(gray, rho, payload, rng):
    """비용맵 rho로 payload(bpp)를 만족하는 λ를 이분탐색, 최소비용 ±1 은닉(STC 시뮬레이터). HILL/WOW/S-UNIWARD 공유 코어."""
    target = payload * gray.size
    lo, hi = 1e-3, 1e3
    for _ in range(60):
        lam = (lo * hi) ** 0.5
        e = np.exp(-lam * rho)
        p = e / (1 + 2 * e)
        if _ternary_entropy(p) > target:
            lo = lam
        else:
            hi = lam
    u = rng.random(gray.shape)
    y = gray.astype(np.int16) + (u < p) - ((u >= p) & (u < 2 * p))
    return np.clip(y, 0, 255).astype(np.uint8)


def simulate_hill(gray, payload, rng):
    """HILL 적응형 은닉 시뮬레이션(학습/평가용). payload bpp의 랜덤 페이로드를 질감 영역에 ±1 매립."""
    return _embed_adaptive(gray, _cost_hill(gray.astype(np.float64)), payload, rng)


def simulate_wow(gray, payload, rng):
    """WOW 적응형 은닉 시뮬레이션(학습/평가용)."""
    return _embed_adaptive(gray, _cost_wow(gray.astype(np.float64)), payload, rng)


def simulate_suniward(gray, payload, rng):
    """S-UNIWARD 적응형 은닉 시뮬레이션(학습/평가용)."""
    return _embed_adaptive(gray, _cost_suniward(gray.astype(np.float64)), payload, rng)


# 라벨 코퍼스 생성기(tools/make_corpus.py)에서 참조하는 표준 시뮬레이터 레지스트리.
SIMULATORS = {"lsbm": simulate_lsbm, "hill": simulate_hill, "wow": simulate_wow, "suniward": simulate_suniward}


# =========================================================================
# 추론 (자투리 타일 배제 + Top-K 집계 + 커버 FPR 보정)
# =========================================================================
def _load():
    global _model
    if _model is None:
        import joblib
        _model = joblib.load(MODEL_PATH)   # 자체 학습한 로컬 파일만 로드
    return _model


def _extract_tiles(g, tile=512, min_tile=256, max_tiles=16):
    """
    자투리 타일(<256px) 배제 + 타일 간 중첩(overlap) 0% 보장.
    - 256 <= h, w < 512: 전체 이미지를 단일 타일로 사용.
    - h, w >= 512: step=tile 비중첩 격자로만 추출 → top-2 평균 시 동일 영역 중복 집계 방지
      (가장자리 자투리 <512는 버림. 학습 스케일 512²와 일관성 유지).
    - 타일이 많으면 고주파 질감 에너지가 높은 상위 max_tiles개를 선택.
    """
    h, w = g.shape
    if h < min_tile or w < min_tile:
        return []
    th, tw = min(tile, h), min(tile, w)
    ys = list(range(0, h - th + 1, th))
    xs = list(range(0, w - tw + 1, tw))

    candidates = []
    for y in ys:
        for x in xs:
            t = g[y:y + th, x:x + tw]
            # 질감 활성도(수평/수직 1차 차분 절댓값 평균)
            act = float(np.abs(t[:, :-1].astype(np.int16) - t[:, 1:].astype(np.int16)).mean())
            candidates.append((act, t))
    candidates.sort(key=lambda item: item[0], reverse=True)
    return [t for _, t in candidates[:max_tiles]]


def _topk_mean(vals, k=2):
    """단일 이상치 타일 오탐을 억제하기 위한 상위 k개 타일 평균."""
    if not vals:
        return 0.0
    s = sorted(vals, reverse=True)[:min(k, len(vals))]
    return float(sum(s) / len(s))


def _calibrate_prob(raw_p, thr_med, thr_high):
    """
    커버 분포 기준 분위수 임계값(thr_med=MEDIUM/FPR≈2.5%, thr_high=HIGH/FPR≈0.5%)을
    engine.py의 판정선(0.75 / 0.90)에 구간 선형 매핑한다.
    """
    thr_med = max(1e-4, min(0.999, float(thr_med)))
    thr_high = max(thr_med + 1e-4, min(0.9999, float(thr_high)))
    p = float(raw_p)
    if p <= thr_med:
        return 0.75 * (p / thr_med)
    if p <= thr_high:
        return 0.75 + 0.15 * ((p - thr_med) / (thr_high - thr_med))
    return min(1.0, 0.90 + 0.10 * ((p - thr_high) / (1.0 - thr_high)))


def predict(img, tile=512):
    """
    PIL 이미지 → (보정 은닉 확률 0~1, 설명).
    - 최소 256x256 이상 온전한 타일만 사용(자투리 타일 배제).
    - 타일별 확률의 Top-2 평균을 구한 뒤, 커버 FPR 보정 임계값 기준으로 0~1 확률로 변환.
    - v2 듀얼 헤드(lsbm/hill)와 레거시 단일 헤드("clf") 모두 호환.
    """
    if not available():
        return None
    model = _load()
    g = np.asarray(img.convert("L"))
    tiles = _extract_tiles(g, tile=tile, min_tile=256, max_tiles=16)
    if not tiles:
        return None

    feat_mode = model.get("feature_mode", "spam686")
    X = np.stack([extract_features(t, mode=feat_mode) for t in tiles])

    heads = model.get("heads")
    if heads:
        best_cal, best_raw, best_name = -1.0, 0.0, ""
        head_labels = {"lsbm": "LSBM/±1", "hill": "HILL/적응형"}
        parts = []
        for hkey in ("lsbm", "hill"):
            if hkey not in heads:
                continue
            hinfo = heads[hkey]
            tile_probs = hinfo["clf"].predict_proba(X)[:, 1].tolist()
            raw_p = _topk_mean(tile_probs, k=2)
            cal_p = _calibrate_prob(raw_p, hinfo.get("thr_med", 0.75), hinfo.get("thr_high", 0.90))
            lbl = head_labels.get(hkey, hkey.upper())
            parts.append(f"{lbl}={cal_p:.3f}(raw {raw_p:.3f})")
            if cal_p > best_cal:
                best_cal, best_raw, best_name = cal_p, raw_p, lbl
        desc = (f"2-Head[{best_name} 우세: {', '.join(parts)}] "
                f"({len(tiles)}개 타일 top-2 평균) | 학습: {model.get('info', '')}")
        return best_cal, desc

    # 레거시 단일 헤드 폴백
    tile_probs = model["clf"].predict_proba(X)[:, 1].tolist()
    prob = _topk_mean(tile_probs, k=2)
    return prob, f"SPAM686 분류기 ({len(tiles)}개 타일, top-2 평균) | 학습: {model.get('info', '')}"


def _demo():
    """은닉 시뮬레이터 자가검증: 평탄/질감 반반 이미지에서 적응형이 질감 영역에 변경을 몰고 bpp를 대략 만족하는지."""
    rng = np.random.default_rng(0)
    g = np.full((256, 256), 128, np.uint8)
    g[:, 128:] = rng.integers(0, 256, (256, 128), dtype=np.uint8)  # 오른쪽 절반만 질감
    for name in ("lsbm", "hill", "wow", "suniward"):
        y = SIMULATORS[name](g, 0.3, np.random.default_rng(1))
        ch = (y.astype(int) != g.astype(int))
        frac = ch.mean()
        assert 0 < frac < 0.5, f"{name}: 변경비율 비정상 {frac}"
        if name != "lsbm":  # 적응형은 질감(오른쪽)에 집중되어야 함
            right = ch[:, 128:].sum() / ch.sum()
            assert right > 0.8, f"{name}: 질감 집중 실패 right={right:.2f}"
    print("ml demo OK - LSBM/HILL/WOW/S-UNIWARD simulators pass")


if __name__ == "__main__":
    _demo()
