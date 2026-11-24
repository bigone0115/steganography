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


def _ternary_change_probs(rho, target_bits):
    """비용맵 rho에서 엔트로피=target_bits가 되는 λ를 이분탐색해 위치별 +1/-1 변경확률 p 반환(STC 시뮬레이터 코어)."""
    lo, hi = 1e-3, 1e3
    for _ in range(60):
        lam = (lo * hi) ** 0.5
        e = np.exp(-lam * rho)
        p = e / (1 + 2 * e)
        if _ternary_entropy(p) > target_bits:
            lo = lam
        else:
            hi = lam
    return p


def _ternary_apply(x, p, rng):
    """확률 p로 +1, p로 -1 변경(정수 배열)."""
    u = rng.random(x.shape)
    return x + (u < p) - ((u >= p) & (u < 2 * p))


def _embed_adaptive(gray, rho, payload, rng):
    """비용맵 rho로 payload(bpp)를 만족하는 최소비용 ±1 은닉 시뮬레이션. HILL/WOW/S-UNIWARD 공유 코어."""
    p = _ternary_change_probs(rho, payload * gray.size)
    return np.clip(_ternary_apply(gray.astype(np.int16), p, rng), 0, 255).astype(np.uint8)


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
    _demo_jpeg()


# =========================================================================
# JPEG 전용 스테그분석 — DCTR 8000차원 특징(Holub & Fridrich 2015) + QF별 분류기
# 공간 도메인 모델은 JPEG에서 오탐이 나므로, JPEG은 양자화 DCT 계수 기반 별도 모델을 쓴다.
# 시뮬레이터(nsF5/UERD/J-UNIWARD)는 메모리상 계수 배열만 바꾸며 파일을 쓰지 않는다 — 탐지기 학습 전용(가드레일 B).
# =========================================================================
JPEG_MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "jpeg_clf.joblib")
JPEG_MAX_BLOCKS = 16384   # ponytail: 상단 ~1024x1024 영역만 디코딩(순수 Python 디코더 속도 상한). 큰 사진 전체는 디코더 가속 후

_jpeg_model = None


def jpeg_available():
    return NUMPY_OK and os.path.isfile(JPEG_MODEL_PATH)


if NUMPY_OK:
    # 8x8 직교 DCT-II 행렬: 계수 F = D·X·Dᵀ, 복원 X = Dᵀ·F·D (JPEG 정의와 동일)
    _D8 = np.array([[(np.sqrt(1 / 8) if k == 0 else np.sqrt(2 / 8)) * np.cos((2 * n + 1) * k * np.pi / 16)
                     for n in range(8)] for k in range(8)])
    # 지그재그 k번째 → 자연순서 위치(행*8+열)
    _ZZ = np.array(sorted(range(64), key=lambda p: (p // 8 + p % 8,
                                                    (p // 8) if (p // 8 + p % 8) % 2 else (p % 8))))
    # 위상 접기(DCTR 대칭 병합): 0..7 → 0,1,2,3,4,3,2,1 → (a,b) 25개 클래스
    _FOLD = np.array([0, 1, 2, 3, 4, 3, 2, 1])
    # J-UNIWARD용 Daubechies 8 웨이블릿 필터(공개 참조구현과 동일 계수)
    _HPDF = np.array([-0.0544158422, 0.3128715909, -0.6756307363, 0.5853546837, 0.0158291053, -0.2840155430,
                      -0.0004724846, 0.1287474266, 0.0173693010, -0.0440882539, -0.0139810279, 0.0087460940,
                      0.0048703530, -0.0003917404, -0.0006754494, -0.0001174768])
    _LPDF = ((-1) ** np.arange(16)) * _HPDF[::-1]
    _DB8_BANK = [np.outer(_LPDF, _HPDF), np.outer(_HPDF, _LPDF), np.outer(_HPDF, _HPDF)]

# IJG 표준 휘도 양자화표(QF50, 자연순서) — QF 추정용
_STD_LUMA = [16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
             14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
             49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99]


def ijg_table(qf):
    """IJG 품질계수(QF) → 8x8 휘도 양자화표(자연순서)."""
    s = 5000 // qf if qf < 50 else 200 - 2 * qf
    return np.clip((np.array(_STD_LUMA) * s + 50) // 100, 1, 255).reshape(8, 8)


def estimate_qf(q):
    """양자화표 → (가장 가까운 IJG QF, 평균 절대오차). 오차가 크면 비표준(카메라 자체) 표."""
    err, qf = min((float(np.abs(ijg_table(f) - q).mean()), f) for f in range(1, 101))
    return qf, err


def jpeg_luma(data, max_blocks=JPEG_MAX_BLOCKS):
    """JPEG 바이트 → (휘도 양자화 계수 2D 배열[8bh x 8bw, 자연순서], 8x8 양자화표) 또는 None."""
    import io
    from PIL import Image
    from . import steganalysis
    res = steganalysis.jpeg_dct_coefficients(data, max_blocks=max_blocks, component=0, with_width=True)
    if not res or not res[0] or not res[1]:
        return None
    blocks, bw = res
    bh = len(blocks) // bw
    if bh < 2 or bw < 2:
        return None
    zz = np.asarray(blocks[:bh * bw], dtype=np.int32)
    nat = np.empty_like(zz)
    nat[:, _ZZ] = zz
    coef = nat.reshape(bh, bw, 8, 8).transpose(0, 2, 1, 3).reshape(bh * 8, bw * 8)
    try:
        q = np.array(Image.open(io.BytesIO(data)).quantization[0]).reshape(8, 8)   # Pillow는 자연순서로 반환
    except Exception:
        return None
    return coef, q


def _blocks(a):
    """(8bh x 8bw) → (bh, bw, 8, 8) 블록 뷰."""
    h, w = a.shape
    return a.reshape(h // 8, 8, w // 8, 8).transpose(0, 2, 1, 3)


def _unblocks(b):
    bh, bw = b.shape[:2]
    return b.transpose(0, 2, 1, 3).reshape(bh * 8, bw * 8)


def jpeg_decompress(coef, q):
    """양자화 계수 → 반올림·클리핑 없는 공간 이미지(-128 기준, DCTR·J-UNIWARD 정의)."""
    b = _blocks(coef.astype(np.float64)) * q
    return _unblocks(np.einsum("ki,abkl,lj->abij", _D8, b, _D8))


def dctr_features(coef, q, qf, T=4):
    """
    DCTR: 복원 이미지에 64개 DCT 기저 필터를 전 위치(비데시메이트) 적용 → |응답|/qs 반올림·T 절단 →
    기저(64) x 위상 클래스(25) x 빈(T+1=5) 정규화 히스토그램 = 8000차원.
    8x8 기저 필터 응답 = 위상 (a,b)만큼 밀린 격자에서의 블록 DCT 이므로 64번의 블록 DCT로 계산.
    """
    x = jpeg_decompress(coef, q)
    qs = 8 * (2 - max(50, qf) / 50)          # DCTR 원 논문의 QF별 양자화 스텝(QF75 → 4)
    H, W = x.shape
    hist = np.zeros((64, 25, T + 1))
    kl = np.arange(64)[:, None] * (T + 1)
    for a in range(8):
        for b in range(8):
            nh, nw = (H - a) // 8, (W - b) // 8
            blk = x[a:a + 8 * nh, b:b + 8 * nw].reshape(nh, 8, nw, 8).transpose(0, 2, 1, 3)
            u = np.einsum("ki,abij,lj->abkl", _D8, blk, _D8).reshape(-1, 64).T      # (64 기저, 위치수)
            v = np.minimum(np.rint(np.abs(u) / qs), T).astype(np.int64)
            hist[:, _FOLD[a] * 5 + _FOLD[b]] += np.bincount((kl + v).ravel(), minlength=64 * (T + 1)).reshape(64, T + 1)
    tot = hist.sum(axis=2, keepdims=True)
    return (hist / np.where(tot > 0, tot, 1)).ravel().astype(np.float32)


def _nz_ac(coef):
    nz = coef != 0
    nz[::8, ::8] = False
    return int(nz.sum())


def _inv_binary_entropy(h):
    lo, hi = 1e-12, 0.5
    for _ in range(50):
        m = (lo + hi) / 2
        e = -m * np.log2(m) - (1 - m) * np.log2(1 - m)
        lo, hi = (m, hi) if e < h else (lo, m)
    return lo


def simulate_nsf5(coef, q, alpha, rng):
    """nsF5 시뮬레이션(학습용): alpha bpnzAC 랜덤 페이로드 → 0 아닌 AC 계수 일부의 절댓값을 1 감소(웨트페이퍼 최적 효율 가정)."""
    nz = coef != 0
    nz[::8, ::8] = False
    idx = np.flatnonzero(nz)
    n_ch = int(round(_inv_binary_entropy(min(alpha, 1.0)) * idx.size))
    pick = rng.choice(idx, size=n_ch, replace=False)
    y = coef.copy().ravel()
    y[pick] -= np.sign(y[pick])
    return y.reshape(coef.shape)


def _cost_uerd(coef, q):
    """UERD(Guo 2015): 모드 양자화 스텝 / (블록 AC 에너지 + 0.25·8이웃 에너지 합). 평탄 블록(에너지 0)은 웨트."""
    b = _blocks(np.abs(coef).astype(np.float64)) * q
    e = b.sum(axis=(2, 3)) - b[:, :, 0, 0]
    p = np.pad(e, 1, mode="edge")
    nb = sum(p[1 + dy:1 + dy + e.shape[0], 1 + dx:1 + dx + e.shape[1]]
             for dy in (-1, 0, 1) for dx in (-1, 0, 1) if dy or dx)
    qm = q.astype(np.float64).copy()
    qm[0, 0] = 0.5 * (q[0, 1] + q[1, 0])
    with np.errstate(divide="ignore"):
        rho = np.kron(1.0 / (e + 0.25 * nb), np.ones((8, 8))) * np.tile(qm, e.shape)
    return np.minimum(rho, 1e10)


def _cost_juniward(coef, q, sigma=2 ** -6):
    """J-UNIWARD(Holub 2014): 계수 1 변경이 db8 웨이블릿 3부대역에 주는 상대변화 합. 부대역별 FFT 1회로 64모드 상관."""
    x = np.pad(jpeg_decompress(coef, q), 16, mode="symmetric")
    bh, bw = coef.shape[0] // 8, coef.shape[1] // 8
    s = (x.shape[0] + 15 + 22, x.shape[1] + 15 + 22)       # 선형 합성곱이 되도록 충분한 FFT 크기
    rho = np.zeros((bh, bw, 8, 8))
    for f in _DB8_BANK:
        wfull = np.fft.irfft2(np.fft.rfft2(x, s) * np.fft.rfft2(f, s), s)[:x.shape[0] + 15, :x.shape[1] + 15]
        FR = np.fft.rfft2(1.0 / (sigma + np.abs(wfull)), s)
        for i in range(8):
            for j in range(8):
                basis = np.outer(_D8[i], _D8[j]) * q[i, j]
                dw = np.abs(np.fft.irfft2(np.fft.rfft2(basis, (23, 23)) * np.fft.rfft2(f, (23, 23)), (23, 23)))
                # 블록 (m,n) 변경의 부대역 영향은 wfull[8m+16:, 8n+16:]부터 23x23 → 상관값은 full 결과의 +22 위치
                corr = np.fft.irfft2(FR * np.fft.rfft2(dw[::-1, ::-1], s), s)
                rho[:, :, i, j] += corr[38::8, 38::8][:bh, :bw]
    return np.minimum(_unblocks(rho), 1e10)


def _embed_jpeg(coef, rho, alpha, rng):
    return _ternary_apply(coef, _ternary_change_probs(rho, alpha * _nz_ac(coef)), rng)


def simulate_uerd(coef, q, alpha, rng):
    """UERD 적응형 JPEG 은닉 시뮬레이션(학습용, alpha bpnzAC 랜덤 페이로드)."""
    return _embed_jpeg(coef, _cost_uerd(coef, q), alpha, rng)


def simulate_juniward(coef, q, alpha, rng):
    """J-UNIWARD 적응형 JPEG 은닉 시뮬레이션(학습용, alpha bpnzAC 랜덤 페이로드)."""
    return _embed_jpeg(coef, _cost_juniward(coef, q), alpha, rng)


JPEG_SIMULATORS = {"nsf5": simulate_nsf5, "uerd": simulate_uerd, "juniward": simulate_juniward}


def predict_jpeg(data):
    """
    JPEG 바이트 → (보정 은닉 확률 0~1, 설명) 또는 (None, 건너뛴 이유).
    양자화표로 QF를 추정해 가장 가까운 QF 모델을 쓴다. 학습 QF와 ±3 넘게 다르거나 비표준 표면
    판정하지 않는다(학습 조건 밖 = 오탐 원인).
    """
    global _jpeg_model
    if not jpeg_available():
        return None, "JPEG 모델 없음"
    if _jpeg_model is None:
        import joblib
        _jpeg_model = joblib.load(JPEG_MODEL_PATH)   # 자체 학습한 로컬 파일만 로드
    lq = jpeg_luma(data)
    if lq is None:
        return None, "DCT 계수 추출 불가"
    coef, q = lq
    qf, err = estimate_qf(q)
    models = _jpeg_model["models"]
    near = min(models, key=lambda f: abs(f - qf))
    if err > 1.0 or abs(near - qf) > 3:
        return None, f"학습 범위 밖 양자화표(추정 QF {qf}, 표 오차 {err:.1f}; 학습 QF {sorted(models)})"
    m = models[near]
    raw = float(m["clf"].predict_proba(dctr_features(coef, q, near)[None, :])[0, 1])
    cal = _calibrate_prob(raw, m["thr_med"], m["thr_high"])
    return cal, (f"DCTR8000 QF{near} 모델(추정 QF {qf}, 분석 {coef.shape[1]}x{coef.shape[0]}px, raw {raw:.3f}) "
                 f"| 학습: {_jpeg_model.get('info', '')}")


def _demo_jpeg():
    """JPEG 경로 자가검증: 디코더 격자·IDCT가 Pillow 복원과 일치, QF 추정, DCTR 차원, 시뮬레이터 페이로드·적응성."""
    import io
    from PIL import Image
    assert abs(_LPDF.sum() - np.sqrt(2)) < 1e-6 and abs(_HPDF.sum()) < 1e-6, "db8 필터 계수 오류"
    rng = np.random.default_rng(0)
    g = np.full((256, 256), 100.0) + np.add.outer(np.arange(256), np.arange(256)) * 0.1
    g[:, 128:] += rng.normal(0, 25, (256, 128))                    # 오른쪽 절반만 질감
    buf = io.BytesIO()
    Image.fromarray(np.clip(g, 0, 255).astype(np.uint8)).save(buf, "JPEG", quality=75)
    coef, q = jpeg_luma(buf.getvalue())
    assert coef.shape == (256, 256), coef.shape
    assert estimate_qf(q) == (75, 0.0), estimate_qf(q)
    pil = np.asarray(Image.open(io.BytesIO(buf.getvalue())), dtype=np.float64)
    diff = np.abs(np.clip(np.rint(jpeg_decompress(coef, q) + 128), 0, 255) - pil).mean()
    assert diff < 1.0, f"계수 격자/IDCT 불일치 {diff:.2f}"
    f = dctr_features(coef, q, 75)
    assert f.shape == (8000,) and np.allclose(f.reshape(1600, 5).sum(1), 1.0)
    nz = _nz_ac(coef)
    for name, sim in JPEG_SIMULATORS.items():
        y = sim(coef, q, 0.4, np.random.default_rng(1))
        ch = y != coef
        assert 0 < ch.sum() < nz, f"{name}: 변경 수 비정상 {ch.sum()}/{nz}"
        if name != "nsf5":
            right = ch[:, 128:].sum() / ch.sum()
            assert right > 0.8, f"{name}: 질감 집중 실패 right={right:.2f}"
        assert np.abs(dctr_features(y, q, 75) - f).sum() > 0
    print("ml jpeg demo OK - decoder grid, QF estimate, DCTR8000, nsF5/UERD/J-UNIWARD simulators pass")


if __name__ == "__main__":
    _demo()
