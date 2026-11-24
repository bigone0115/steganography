"""
통계적 스테그분석(steganalysis) — 우리 패킷이 아니어도 'LSB 은닉 흔적'을 통계로 탐지.

핵심: 카이제곱(Chi-square) PoV(Pairs of Values) 공격.
자연 이미지/오디오는 값 2k와 2k+1의 빈도가 서로 다르지만, LSB 치환 은닉이 일어나면
두 빈도가 비슷해진다. 이 '평탄화'를 카이제곱 검정으로 수치화해 은닉 가능성을 0~1로 반환한다.

GUI 비의존 순수 함수. scipy 없이 표준 math만 사용(불완전 감마함수 직접 구현).
"""

import math
import re
import struct


# ---- 불완전 감마함수 (카이제곱 p-value 계산용, Numerical Recipes 방식) ----
def _gammln(xx):
    cof = [76.18009172947146, -86.50532032941677, 24.01409824083091,
           -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5]
    x = xx
    y = xx
    tmp = x + 5.5
    tmp -= (x + 0.5) * math.log(tmp)
    ser = 1.000000000190015
    for c in cof:
        y += 1
        ser += c / y
    return -tmp + math.log(2.5066282746310005 * ser / x)


def _gser(a, x):
    if x <= 0:
        return 0.0
    gln = _gammln(a)
    ap = a
    summ = 1.0 / a
    dele = summ
    for _ in range(500):
        ap += 1
        dele *= x / ap
        summ += dele
        if abs(dele) < abs(summ) * 1e-14:
            break
    return summ * math.exp(-x + a * math.log(x) - gln)


def _gcf(a, x):
    gln = _gammln(a)
    FPMIN = 1e-300
    b = x + 1.0 - a
    c = 1.0 / FPMIN
    d = 1.0 / b
    h = d
    for i in range(1, 500):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < FPMIN:
            d = FPMIN
        c = b + an / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        dele = d * c
        h *= dele
        if abs(dele - 1.0) < 1e-14:
            break
    return math.exp(-x + a * math.log(x) - gln) * h


def _gammq(a, x):
    """상위 정규화 불완전 감마함수 Q(a,x). 카이제곱 p-value = Q(dof/2, chi2/2)."""
    if x < 0 or a <= 0:
        return 1.0
    if x < a + 1.0:
        return 1.0 - _gser(a, x)
    return _gcf(a, x)


def chi_square_lsb(data, max_bytes=200000):
    """
    바이트 스트림(픽셀/샘플 값)에 카이제곱 PoV 검정을 적용해 LSB 은닉 '가능성'(0~1)을 반환.
    1에 가까울수록 LSB 치환 은닉 징후가 강함. 자연 데이터는 보통 0에 가깝다.
    반환: (probability, chi2, dof)
    """
    buf = data[:max_bytes]
    if len(buf) < 256:
        return 0.0, 0.0, 0
    freq = [0] * 256
    for b in buf:
        freq[b] += 1

    chi2 = 0.0
    pairs = 0
    for k in range(128):
        a = freq[2 * k]
        b = freq[2 * k + 1]
        tot = a + b
        if tot >= 10:                # 기대도수 E=(a+b)/2 >= 5 (Cochran 규칙): 희소 빈 노이즈 제외
            chi2 += (a - b) ** 2 / tot   # 2셀 합 2*(a-E)^2/E 와 동일 (과거 한 셀만 더해 1/2로 축소된 버그 수정)
            pairs += 1
    dof = pairs - 1
    if dof <= 0:
        return 0.0, 0.0, 0
    prob = _gammq(dof / 2.0, chi2 / 2.0)
    return prob, chi2, dof


def chi_square_windows(data, window=65536, step=32768, max_bytes=3000000):
    """
    데이터를 윈도우로 나눠 각 구간의 카이제곱 은닉가능성을 구하고 최댓값을 반환.
    LSB 은닉은 보통 앞에서부터 순차 삽입되므로, 부분 은닉도 해당 구간에서 포착된다.
    반환: (best_prob, best_chi2, best_offset)
    """
    data = data[:max_bytes]
    n = len(data)
    if n < window:
        p, c, _ = chi_square_lsb(data)
        return p, c, 0
    best = (0.0, 0.0, 0)
    i = 0
    while i + window <= n:
        p, c, _ = chi_square_lsb(data[i:i + window])
        if p > best[0]:
            best = (p, c, i)
        i += step
    return best


def lsb_one_ratio(lsb_bytes):
    """추출한 LSB 바이트에서 1비트 비율을 반환(0.5 근처 + 고엔트로피면 무작위 페이로드 의심)."""
    if not lsb_bytes:
        return 0.0
    ones = 0
    for b in lsb_bytes:
        ones += bin(b).count("1")
    return ones / (len(lsb_bytes) * 8)


def assess(carrier_bytes, lsb_sample=None):
    """
    종합 판정 헬퍼. 카이제곱 확률과 LSB 비트비율로 (등급, 메시지)를 돌려준다.
    등급: 'HIGH' | 'MEDIUM' | None
    """
    prob, chi2, off = chi_square_windows(carrier_bytes)
    ratio = lsb_one_ratio(lsb_sample) if lsb_sample else None
    ratio_txt = f", LSB 1비트율={ratio:.3f}" if ratio is not None else ""
    msg = f"Chi-square 은닉가능성={prob:.3f} (최대구간 chi2={chi2:.1f} @0x{off:X}){ratio_txt}"
    if prob >= 0.95:
        return "HIGH", msg
    if prob >= 0.80:
        return "MEDIUM", msg
    return None, msg


# =========================================================================
# RS 분석 (Fridrich) — 무작위로 흩뿌린 LSB 은닉도 탐지 + 은닉 비율 추정
# =========================================================================
def _rs_counts(chan, mask, flip_all=False):
    """chan: 한 채널 값 리스트. 4픽셀 그룹마다 F_M 적용 전후 '거칠기'를 비교해 (R, S) 비율 반환."""
    r = s = n = 0
    for i in range(0, len(chan) - 3, 4):
        g = chan[i:i + 4]
        if flip_all:
            g = [x ^ 1 for x in g]
        before = abs(g[1] - g[0]) + abs(g[2] - g[1]) + abs(g[3] - g[2])
        h = [(x ^ 1 if m == 1 else ((x + 1) ^ 1) - 1 if m == -1 else x) for x, m in zip(g, mask)]
        after = abs(h[1] - h[0]) + abs(h[2] - h[1]) + abs(h[3] - h[2])
        if after > before:
            r += 1
        elif after < before:
            s += 1
        n += 1
    return (r / n, s / n) if n else (0.0, 0.0)


def rs_analysis(pixels, channels=3, max_per_channel=120000):
    """
    RS 스테그분석. pixels: 인터리브된 RGB 바이트. 반환: 추정 은닉 비율 p(0~1, 채널 평균).
    카이제곱은 '앞에서부터 순차 은닉'에 강하고, RS는 '무작위 위치 은닉'의 은닉량도 추정한다.
    """
    mask = [0, 1, 1, 0]
    neg = [-m for m in mask]
    ests = []
    for c in range(channels):
        chan = list(pixels[c::channels][:max_per_channel])
        if len(chan) < 1024:
            continue
        rm, sm = _rs_counts(chan, mask)
        rn, sn = _rs_counts(chan, neg)
        rm1, sm1 = _rs_counts(chan, mask, True)
        rn1, sn1 = _rs_counts(chan, neg, True)
        d0, d1 = rm - sm, rm1 - sm1
        e0, e1 = rn - sn, rn1 - sn1
        a = 2 * (d1 + d0)
        b = e0 - e1 - d1 - 3 * d0
        cc = d0 - e0
        if abs(a) < 1e-12:
            continue
        disc = b * b - 4 * a * cc
        if disc < 0:
            continue
        z = min(((-b + math.sqrt(disc)) / (2 * a), (-b - math.sqrt(disc)) / (2 * a)), key=abs)
        if abs(z - 0.5) < 1e-12:
            continue
        ests.append(max(0.0, min(1.0, z / (z - 0.5))))
    return sum(ests) / len(ests) if ests else 0.0


# =========================================================================
# JPEG DCT 계수 기반 탐지 (JSteg / F5) — 순수 Python JPEG 엔트로피 디코더 (baseline + progressive)
# =========================================================================
_ZZ_LOWFREQ = (1, 2, 4)   # 지그재그 인덱스: (0,1), (1,0), (1,1) 저주파 AC


class _Bits:
    """RST 마커로 나뉜 세그먼트(바이트 스터핑 제거됨)를 비트 단위로 읽는다."""

    def __init__(self, segments):
        self.segs = segments
        self.si = 0
        self.seg = segments[0] if segments else b""
        self.pos = 0
        self.nbits = len(self.seg) * 8

    def next_segment(self):
        self.si += 1
        if self.si >= len(self.segs):
            raise EOFError
        self.seg = self.segs[self.si]
        self.pos = 0
        self.nbits = len(self.seg) * 8

    def bit(self):
        p = self.pos
        if p >= self.nbits:
            raise EOFError
        self.pos = p + 1
        return (self.seg[p >> 3] >> (7 - (p & 7))) & 1

    def bits(self, k):
        v = 0
        for _ in range(k):
            v = (v << 1) | self.bit()
        return v

    def huff(self, table):
        code = 0
        for length in range(1, 17):
            code = (code << 1) | self.bit()
            sym = table.get((length, code))
            if sym is not None:
                return sym
        raise ValueError("bad huffman")


def _extend(v, t):
    return v - (1 << t) + 1 if t and v < (1 << (t - 1)) else v


def jpeg_dct_coefficients(data, max_blocks=6000, component=None, with_width=False):
    """
    JPEG(baseline + progressive)에서 양자화된 DCT 계수 블록(각 64개, 지그재그 순서)을 추출.
    이미지 위쪽부터 휘도 블록이 약 max_blocks개가 되는 영역까지만 디코딩(속도 상한).
    component=None이면 모든 성분, 0이면 휘도(Y)만. 산술부호화 등 미지원이면 None.
    with_width=True(성분 지정 시)면 (블록목록, 블록 열 수)를 반환 — 2D 격자 복원용(ML DCTR 특징).
    """
    if data[:2] != b"\xff\xd8":
        return None
    pos, n = 2, len(data)
    huff, comps, restart = {}, [], 0
    frame = None
    coefs = None
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            return None
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker == 0xD9:
            break
        seglen = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        seg = data[pos + 4:pos + 2 + seglen]
        if marker in (0xC0, 0xC1, 0xC2):
            hgt, wid = struct.unpack(">HH", seg[1:5])
            for i in range(seg[5]):
                hv = seg[7 + i * 3]
                comps.append({"id": seg[6 + i * 3], "h": hv >> 4, "v": hv & 15})
            hmax = max(c["h"] for c in comps)
            vmax = max(c["v"] for c in comps)
            mcux = -(-wid // (8 * hmax))
            mcuy_full = -(-hgt // (8 * vmax))
            luma = comps[0]
            # 휘도 블록이 max_blocks개쯤 되도록 MCU 행 수 제한
            mcuy = min(mcuy_full, max(1, -(-max_blocks // (mcux * luma["h"] * luma["v"]))))
            for c in comps:
                c["bw"] = -(-(-(-wid * c["h"] // hmax)) // 8)       # 실제 블록 열 수
                c["bh_full"] = -(-(-(-hgt * c["v"] // vmax)) // 8)
                c["aw"] = mcux * c["h"]                              # 할당 폭(MCU 패딩 포함)
                c["ah"] = mcuy * c["v"]                              # 디코딩할 블록 행 수
                c["blocks"] = [[0] * 64 for _ in range(c["aw"] * c["ah"])]
            frame = {"mcux": mcux, "mcuy": mcuy, "progressive": marker == 0xC2}
        elif 0xC3 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            return None                                             # lossless/산술부호화 미지원
        elif marker == 0xC4:
            p = 0
            while p < len(seg):
                tc_th = seg[p]
                counts = seg[p + 1:p + 17]
                p += 17
                table, code = {}, 0
                for length in range(1, 17):
                    for _ in range(counts[length - 1]):
                        table[(length, code)] = seg[p]
                        p += 1
                        code += 1
                    code <<= 1
                huff[(tc_th >> 4, tc_th & 15)] = table
        elif marker == 0xDD:
            restart = struct.unpack(">H", seg[:2])[0]
        elif marker == 0xDA:
            if frame is None:
                return None
            ns = seg[0]
            byid = {c["id"]: c for c in comps}
            scomps = []
            for i in range(ns):
                c = byid.get(seg[1 + i * 2])
                if c is None:
                    return None
                scomps.append((c, seg[2 + i * 2] >> 4, seg[2 + i * 2] & 15))
            ss, se, ahal = seg[1 + ns * 2], seg[2 + ns * 2], seg[3 + ns * 2]
            body_start = pos + 2 + seglen
            m = re.compile(rb"\xff[^\x00\xd0-\xd7]").search(data, body_start)
            body_end = m.start() if m else n
            segments = [s.replace(b"\xff\x00", b"\xff")
                        for s in re.split(rb"\xff[\xd0-\xd7]", data[body_start:body_end])]
            try:
                _decode_scan(frame, scomps, huff, restart, segments, ss, se, ahal >> 4, ahal & 15)
            except KeyError:
                return None
            pos = body_end
            continue
        pos += 2 + seglen
    if frame is None:
        return None
    out = []
    for idx, c in enumerate(comps):
        if component is not None and idx != component:
            continue
        rows = min(c["ah"], c["bh_full"])
        for r in range(rows):
            out.extend(c["blocks"][r * c["aw"]:r * c["aw"] + c["bw"]])
    if with_width:
        return out, (comps[component]["bw"] if component is not None else 0)
    return out


def _decode_scan(frame, scomps, huff, restart, segments, ss, se, ah, al):
    """한 스캔(SOS)을 디코딩해 각 성분의 계수 블록 배열을 채운다 (baseline/progressive 공용)."""
    bits = _Bits(segments)
    progressive = frame["progressive"]
    state = {"eobrun": 0, "acstate": 0, "acnext": 0}
    preds = {}

    def reset():
        state.update(eobrun=0, acstate=0, acnext=0)
        for c, _, _ in scomps:
            preds[c["id"]] = 0

    def decode_block(c, td, ta, blk):
        cid = c["id"]
        if not progressive:                          # baseline: DC + AC 전체
            t = bits.huff(huff[(0, td)])
            preds[cid] += _extend(bits.bits(t), t)
            blk[0] = preds[cid]
            k = 1
            while k < 64:
                rs = bits.huff(huff[(1, ta)])
                r, s = rs >> 4, rs & 15
                if s == 0:
                    if r == 15:
                        k += 16
                        continue
                    break
                k += r
                if k > 63:
                    break
                blk[k] = _extend(bits.bits(s), s)
                k += 1
            return
        if ss == 0:                                  # DC 스캔
            if ah == 0:
                t = bits.huff(huff[(0, td)])
                preds[cid] += _extend(bits.bits(t), t) if t else 0
                blk[0] = preds[cid] << al
            elif bits.bit():
                blk[0] |= 1 << al
            return
        if ah == 0:                                  # AC 최초 스캔
            if state["eobrun"] > 0:
                state["eobrun"] -= 1
                return
            k = ss
            while k <= se:
                rs = bits.huff(huff[(1, ta)])
                r, s = rs >> 4, rs & 15
                if s == 0:
                    if r < 15:
                        state["eobrun"] = bits.bits(r) + (1 << r) - 1
                        break
                    k += 16
                    continue
                k += r
                if k > 63:
                    break
                blk[k] = _extend(bits.bits(s), s) * (1 << al)
                k += 1
            return
        # AC 정밀화 스캔 (successive approximation)
        k, r = ss, 0
        while k <= se:
            z = blk[k]
            sign = -1 if z < 0 else 1
            st = state["acstate"]
            if st == 0:
                rs = bits.huff(huff[(1, ta)])
                s, r = rs & 15, rs >> 4
                if s == 0:
                    if r < 15:
                        state["eobrun"] = bits.bits(r) + (1 << r)
                        state["acstate"] = 4
                    else:
                        r = 16
                        state["acstate"] = 1
                else:
                    state["acnext"] = _extend(bits.bits(s), s)
                    state["acstate"] = 2 if r else 3
                continue
            if st in (1, 2):
                if z:
                    blk[k] += sign * (bits.bit() << al)
                else:
                    r -= 1
                    if r == 0:
                        state["acstate"] = 3 if st == 2 else 0
            elif st == 3:
                if z:
                    blk[k] += sign * (bits.bit() << al)
                else:
                    blk[k] = state["acnext"] << al
                    state["acstate"] = 0
            elif st == 4 and z:
                blk[k] += sign * (bits.bit() << al)
            k += 1
        if state["acstate"] == 4:
            state["eobrun"] -= 1
            if state["eobrun"] == 0:
                state["acstate"] = 0

    reset()
    mcu_count = 0
    try:
        if len(scomps) == 1:                         # 비인터리브: 성분 블록을 래스터 순서로
            c, td, ta = scomps[0]
            rows = min(c["ah"], c["bh_full"])
            for r_ in range(rows):
                for col in range(c["bw"]):
                    if restart and mcu_count and mcu_count % restart == 0:
                        bits.next_segment()
                        reset()
                    decode_block(c, td, ta, c["blocks"][r_ * c["aw"] + col])
                    mcu_count += 1
        else:                                        # 인터리브: MCU 단위
            for my in range(frame["mcuy"]):
                for mx in range(frame["mcux"]):
                    if restart and mcu_count and mcu_count % restart == 0:
                        bits.next_segment()
                        reset()
                    for c, td, ta in scomps:
                        for v in range(c["v"]):
                            for h in range(c["h"]):
                                bi = (my * c["v"] + v) * c["aw"] + mx * c["h"] + h
                                decode_block(c, td, ta, c["blocks"][bi])
                    mcu_count += 1
    except (EOFError, ValueError):
        pass


def jsteg_chi_square(blocks):
    """JSteg은 0/1을 제외한 AC 계수의 LSB를 치환 → (2k, 2k+1) 쌍 빈도 평탄화를 카이제곱으로 측정."""
    freq = {}
    for blk in blocks:
        for v in blk[1:]:
            if v not in (0, 1):
                freq[v] = freq.get(v, 0) + 1
    chi2, pairs = 0.0, 0
    for k in range(-64, 64):
        if k == 0:
            continue
        a, b = freq.get(2 * k, 0), freq.get(2 * k + 1, 0)
        tot = a + b
        if tot >= 10:                      # 기대도수 >= 5
            chi2 += (a - b) ** 2 / tot     # 2셀 카이제곱 합 (과거 1/2 누락 수정)
            pairs += 1
    if pairs < 2:
        return 0.0
    return _gammq((pairs - 1) / 2.0, chi2 / 2.0)


def f5_beta(jpeg_bytes):
    """
    F5 탐지(Fridrich 보정 기법): 4px 잘라 같은 양자화표로 재압축한 '보정본'을 원본 추정치로 삼아
    저주파 AC 계수의 h(0)/h(1)/h(2) 변화로 수정 비율 β를 추정. 0 근처면 정상. 실패 시 None.
    """
    try:
        from PIL import Image
        import io as _io
    except ImportError:
        return None
    orig = jpeg_dct_coefficients(jpeg_bytes, component=0)
    if not orig:
        return None
    try:
        img = Image.open(_io.BytesIO(jpeg_bytes))
        q = img.quantization
        w, h = img.size
        if w < 64 or h < 64:
            return None
        buf = _io.BytesIO()
        img.crop((4, 4, w, h)).save(buf, "JPEG", qtables=q)
    except Exception:
        return None
    cal = jpeg_dct_coefficients(buf.getvalue(), component=0)
    if not cal:
        return None

    def hist(blocks, zz):
        hh = [0, 0, 0]
        for blk in blocks:
            a = abs(blk[zz])
            if a < 3:
                hh[a] += 1
        return [x / len(blocks) for x in hh]

    betas = []
    for zz in _ZZ_LOWFREQ:
        h0, h1, _ = hist(orig, zz)
        c0, c1, c2 = hist(cal, zz)
        den = c1 ** 2 + (c2 - c1) ** 2
        if den > 1e-12:
            betas.append((c1 * (h0 - c0) + (h1 - c1) * (c2 - c1)) / den)
    return sum(betas) / len(betas) if betas else None


# =========================================================================
# 오디오: 에코 은닉 / 위상 코딩 탐지
# =========================================================================
def pcm_to_mono(raw, sampwidth, nchannels, max_samples=400000):
    """PCM 바이트를 첫 채널 정수 샘플 리스트로 변환(8/16/24/32bit)."""
    step = sampwidth * nchannels
    out = []
    for i in range(0, min(len(raw), max_samples * step) - step + 1, step):
        b = raw[i:i + sampwidth]
        out.append(b[0] - 128 if sampwidth == 1 else int.from_bytes(b, "little", signed=True))
    return out


def echo_hiding_score(samples, n=16384, min_lag=20, max_lag=400):
    """
    에코 은닉은 1~10ms 고정 지연 에코를 섞는다 → 미분(백색화) 신호 자기상관에 고립된 피크가 생김.
    반환: (z-score, lag). z가 클수록 의심.
    ponytail: 단일 구간 자기상관 휴리스틱. 구간별 지연이 바뀌는 에코는 구간별 켑스트럼으로 고도화 필요.
    """
    import operator
    n = min(n, len(samples) - max_lag - 2)
    if n < 2048:
        return 0.0, 0
    start = (len(samples) - n - max_lag - 1) // 2
    seg = samples[start:start + n + max_lag + 1]
    d = [seg[i + 1] - seg[i] for i in range(len(seg) - 1)]
    energy = sum(map(operator.mul, d[:n], d[:n])) or 1
    r = [sum(map(operator.mul, d[:n], d[lag:lag + n])) / energy for lag in range(min_lag, max_lag)]
    mean = sum(r) / len(r)
    sd = math.sqrt(sum((x - mean) ** 2 for x in r) / len(r)) or 1e-9
    i = max(range(len(r)), key=r.__getitem__)
    return (r[i] - mean) / sd, i + min_lag


def _fft(x):
    n = len(x)
    if n == 1:
        return x
    even, odd = _fft(x[0::2]), _fft(x[1::2])
    out = [0] * n
    for k in range(n // 2):
        t = complex(math.cos(-2 * math.pi * k / n), math.sin(-2 * math.pi * k / n)) * odd[k]
        out[k] = even[k] + t
        out[k + n // 2] = even[k] - t
    return out


def phase_coding_score(samples):
    """
    위상 코딩은 첫 세그먼트의 주파수 위상을 ±π/2로 강제한다 → 위상이 ±π/2(±0.1rad)에 몰린 비율 측정.
    자연음은 약 0.06. 반환: (최대 비율, 세그먼트 길이)
    """
    best = (0.0, 0)
    for n in (256, 512, 1024, 2048, 4096, 8192):
        if len(samples) < n:
            break
        spec = _fft([complex(v, 0) for v in samples[:n]])[1:n // 2]
        thr = sorted(abs(c) for c in spec)[len(spec) // 2]
        sel = [c for c in spec if abs(c) >= thr and abs(c) > 0]
        if not sel:
            continue
        hit = sum(1 for c in sel if abs(abs(math.atan2(c.imag, c.real)) - math.pi / 2) < 0.1)
        if hit / len(sel) > best[0]:
            best = (hit / len(sel), n)
    return best


# =========================================================================
# 텍스트 스테가노그래피: 제로폭 문자 / 줄끝 공백(SNOW) / 동형 문자(homoglyph)
# =========================================================================
ZERO_WIDTH = "​‌‍⁠⁡⁢⁣⁤᠎﻿"


def text_stego_check(text):
    """텍스트에서 은닉 흔적을 찾아 [(등급, 메시지)] 반환."""
    out = []
    if not text:
        return out
    zw = sum(text.count(ch) for ch in ZERO_WIDTH) - (1 if text.startswith("﻿") else 0)
    if zw >= 8:
        out.append(("HIGH", f"제로폭 문자 {zw}개 (비트 인코딩 은닉 의심)"))
    lines = text.splitlines()
    trail = [l for l in lines if l and l != l.rstrip(" \t")]
    tabs = sum(1 for l in trail if "\t" in l[len(l.rstrip(" \t")):])
    if len(trail) >= 5 and (tabs or len(trail) >= len(lines) // 3):
        out.append(("MEDIUM", f"줄끝 공백/탭 {len(trail)}줄 (SNOW 방식 화이트스페이스 은닉 의심)"))
    mixed = 0
    for word in re.findall(r"\w{3,}", text):
        if any("a" <= c.lower() <= "z" for c in word) and \
                any("Ͱ" <= c <= "Ͽ" or "Ѐ" <= c <= "ӿ" for c in word):
            mixed += 1
    if mixed >= 3:
        out.append(("MEDIUM", f"라틴/키릴·그리스 혼용 단어 {mixed}개 (동형 문자 치환 은닉/피싱 의심)"))
    return out


def bytes_as_text(data, max_bytes=2000000):
    """텍스트로 보이는 바이트면 str, 아니면 None (제어문자 비율로 판정)."""
    buf = data[:max_bytes]
    if buf.startswith((b"\xff\xfe", b"\xfe\xff")):
        encs = ("utf-16",)
    else:
        encs = ("utf-8",)
    for enc in encs:
        try:
            t = buf.decode(enc)
        except UnicodeDecodeError:
            continue
        sample = t[:20000]
        bad = sum(1 for c in sample if ord(c) < 32 and c not in "\r\n\t")
        if sample and bad / len(sample) < 0.01:
            return t
    return None


# =========================================================================
# LSB matching(±1) 탐지 — 보정 HCF-COM (Ker 2005)
# =========================================================================
def _hcf_com(hist):
    """히스토그램 특성함수(HCF, DFT 크기)의 무게중심. ±1 은닉은 히스토그램을 뭉개 COM을 낮춘다."""
    n = len(hist)
    num = den = 0.0
    for k in range(1, n // 2 + 1):
        re_ = im_ = 0.0
        for i, h in enumerate(hist):
            if h:
                a = 2 * math.pi * k * i / n
                re_ += h * math.cos(a)
                im_ -= h * math.sin(a)
        mag = math.hypot(re_, im_)
        num += k * mag
        den += mag
    return num / den if den else 0.0


def _adjacency_hist(chan, width, height):
    """수평 인접 픽셀 쌍 (a,b)의 2D 히스토그램 → a-b 차이 분포(511칸)로 축약. 자연 이미지는 0 근처에 뾰족."""
    hist = [0] * 511
    for y in range(height):
        row = chan[y * width:(y + 1) * width]
        for i in range(width - 1):
            hist[row[i] - row[i + 1] + 255] += 1
    return hist


def lsb_matching_score(pixels, width, height, channels=3, max_rows=300):
    """
    보정 HCF-COM. 원본과 2x2 평균 축소본의 COM 비율을 비교한다.
    ±1 은닉은 원본의 고주파 노이즈를 늘려 차이 히스토그램을 넓히지만 축소본에는 영향이 작다
    → 비율(원본/축소)이 작을수록 의심. 반환: 채널 평균 비율(정상 ≈1 이상, 은닉 시 감소).
    ponytail: 단순 1D 차이 히스토그램 버전. 정밀도가 필요하면 2D 인접 히스토그램 HCF로 고도화.
    """
    height = min(height, max_rows)
    if width < 16 or height < 16:
        return None
    ratios = []
    for c in range(channels):
        chan = pixels[c::channels][:width * height]
        ow, oh = width // 2, height // 2
        down = bytearray(ow * oh)
        for y in range(oh):
            r0, r1 = (2 * y) * width, (2 * y + 1) * width
            for x in range(ow):
                down[y * ow + x] = (chan[r0 + 2 * x] + chan[r0 + 2 * x + 1] +
                                    chan[r1 + 2 * x] + chan[r1 + 2 * x + 1]) >> 2
        h_full = _adjacency_hist(chan, width, height)
        h_down = _adjacency_hist(down, ow, oh)
        # 중앙 ±64 구간만(꼬리는 잡음) 사용해 계산량 절감
        c_full = _hcf_com(h_full[255 - 64:255 + 64])
        c_down = _hcf_com(h_down[255 - 64:255 + 64])
        if c_down:
            ratios.append(c_full / c_down)
    return sum(ratios) / len(ratios) if ratios else None


# =========================================================================
# WS(Weighted Stego) 분석 — 소량 LSB 치환에서 RS보다 정확한 은닉률 추정
# =========================================================================
def ws_analysis(pixels, width, height, channels=3, max_rows=400):
    """
    각 픽셀을 4-이웃 평균으로 예측해, LSB 반전값과의 관계로 은닉률 p를 추정(Fridrich-Goljan / Ker).
    p̂ = 2 Σ w(s - s̄)(s - ŝ) / Σ w,  s̄ = LSB 반전값, ŝ = 이웃 예측값, w = 1/(5 + 국소분산).
    반환: (전체 p, [(행 시작, 행 끝, p)] 수평 띠별 국소 추정)
    """
    height = min(height, max_rows)
    if width < 8 or height < 8:
        return 0.0, []
    bands = 8
    band_h = max(2, (height - 2) // bands)
    num_b = [0.0] * bands
    den_b = [0.0] * bands
    for c in range(channels):
        ch = pixels[c::channels][:width * height]
        for y in range(1, height - 1):
            b = min(bands - 1, (y - 1) // band_h)
            base = y * width
            up, dn = base - width, base + width
            for x in range(1, width - 1):
                n1, n2, n3, n4 = ch[up + x], ch[dn + x], ch[base + x - 1], ch[base + x + 1]
                pred = (n1 + n2 + n3 + n4) / 4.0
                var = ((n1 - pred) ** 2 + (n2 - pred) ** 2 + (n3 - pred) ** 2 + (n4 - pred) ** 2) / 4.0
                w = 1.0 / (5.0 + var)
                s = ch[base + x]
                num_b[b] += w * (s - (s ^ 1)) * (s - pred)
                den_b[b] += w
    total = 2 * sum(num_b) / sum(den_b) if sum(den_b) else 0.0
    local = []
    for b in range(bands):
        if den_b[b]:
            local.append((1 + b * band_h, 1 + (b + 1) * band_h, max(0.0, min(1.0, 2 * num_b[b] / den_b[b]))))
    return max(0.0, min(1.0, total)), local


# =========================================================================
# 다중 순서 LSB 스캔 (zsteg 방식) — 도구별 비트 배치를 전수 시도해 시그니처/평문 탐지
# =========================================================================
FILE_MAGICS = {
    b"PK\x03\x04": "ZIP", b"%PDF": "PDF", b"MZ": "PE 실행파일", b"\x7fELF": "ELF 실행파일",
    b"\x89PNG": "PNG", b"\xff\xd8\xff": "JPEG", b"GIF8": "GIF", b"Rar!": "RAR", b"7z\xbc\xaf": "7z",
    b"\x1f\x8b": "GZIP", b"BZh": "BZIP2", b"#!": "스크립트(shebang)", b"<?php": "PHP",
    b"-----BEGIN": "PEM 키/인증서", b"OPENSTEGO": "OpenStego 헤더",
}


def _bits_to_bytes(bitlist, msb_first=True):
    out = bytearray()
    for i in range(0, len(bitlist) - 7, 8):
        v = 0
        chunk = bitlist[i:i + 8] if msb_first else bitlist[i:i + 8][::-1]
        for b in chunk:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def multi_order_lsb_scan(pixels, width, height, channels=3, nbytes=256):
    """
    채널 조합(RGB/BGR/R/G/B) × 비트(0/1) × 비트순서(MSB/LSB 우선) × 행/열 우선으로 앞부분을 추출해
    파일 시그니처(오프셋 0 또는 4바이트 길이 접두 뒤)나 읽을 수 있는 평문이 나오는지 확인.
    반환: [(설정 설명, 결과 설명, 미리보기 바이트)]
    """
    names = "RGB"[:channels]
    combos = [("RGB", list(range(channels))), ("BGR", list(range(channels))[::-1])]
    combos += [(names[c], [c]) for c in range(channels)]
    need_px = nbytes * 8
    hits = []
    for order in ("row", "col"):
        if order == "row":
            idxs = range(min(width * height, need_px))
        else:
            idxs = [y * width + x for x in range(width) for y in range(height)][:need_px]
        for cname, chs in combos:
            for bit in (0, 1):
                bits = []
                for p in idxs:
                    base = p * channels
                    for c in chs:
                        bits.append((pixels[base + c] >> bit) & 1)
                    if len(bits) >= need_px:
                        break
                for msb in (True, False):
                    data = _bits_to_bytes(bits, msb)
                    label = f"{cname} b{bit} {'MSB' if msb else 'LSB'}우선 {'행' if order == 'row' else '열'}순서"
                    found = None
                    for off in (0, 4):
                        for mg, nm in FILE_MAGICS.items():
                            if data[off:off + len(mg)] == mg and (len(mg) >= 3 or off == 0):
                                found = f"{nm} 시그니처 @+{off}"
                                break
                        if found:
                            break
                    if not found:
                        head = data[:48]
                        printable = sum(1 for b in head if 32 <= b <= 126 or b in (9, 10, 13))
                        letters = sum(1 for b in head if 65 <= b <= 90 or 97 <= b <= 122)
                        if len(head) == 48 and printable >= 46 and letters >= 20:
                            found = "평문 텍스트"
                        else:
                            for off in (4, 2):          # 길이 접두 + 텍스트
                                h2 = data[off:off + 40]
                                if sum(1 for b in h2 if 32 <= b <= 126) >= 39 and \
                                        sum(1 for b in h2 if 65 <= b <= 90 or 97 <= b <= 122) >= 18:
                                    found = f"길이접두({off}B) + 평문 텍스트"
                                    break
                    if found:
                        hits.append((label, found, data[:64]))
    return hits
