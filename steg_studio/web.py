"""
웹 UI — 데스크톱 Qt GUI와 같은 탭 구성/테마를 브라우저로 제공. 표준 라이브러리(http.server)만 사용.

도커 컨테이너처럼 화면이 없는 환경에서 GUI 대신 쓴다.
    python -m steg_studio web                      (http://127.0.0.1:47821)
    docker run --rm -p 127.0.0.1:47821:47821 steg-studio web --host 0.0.0.0

탭: 정밀 포렌식 스캐너 / 디렉터리 일괄 스캔 / 메타데이터 / 설정.
'파일·코드 은닉' 탭은 웹에 노출하지 않는다(방어 도구 범위 — 네트워크로 여는 서버에 은닉 기능을 두지 않음).

안전 원칙: 업로드 파일은 임시 폴더에서 '분석만' 하고 절대 실행하지 않으며 응답 직후 삭제한다.
리포트 HTML은 스크립트가 막힌 sandbox iframe에, 나머지 문자열은 textContent로만 표시한다.
이미지 미리보기는 래스터 포맷(PNG/JPEG/GIF/BMP/WebP)만 허용(SVG 스크립트 차단).
"""

import os
import re
import json
import time
import base64
import tempfile
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

from . import engine, analysis, __version__

DEFAULT_PORT = 47821
MAX_UPLOAD = 100 * 1024 * 1024    # 업로드 상한 100MB (엔진 상한 256MB보다 작게: 시연·메모리 여유)
MAX_ITEM_B64 = 20 * 1024 * 1024   # 탐지 항목 다운로드용 원본 동봉 상한(항목당)
_ICON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "steganography_icon.png")   # 앱 아이콘(GUI와 동일)

_IMG_SIGS = ((b"\x89PNG\r\n\x1a\n", "image/png"), (b"\xff\xd8\xff", "image/jpeg"),
             (b"GIF87a", "image/gif"), (b"GIF89a", "image/gif"), (b"BM", "image/bmp"))


def _raster_mime(data):
    """미리보기 가능한 래스터 이미지면 MIME, 아니면 None (SVG 등 스크립트 가능 포맷 제외)."""
    for sig, mime in _IMG_SIGS:
        if data.startswith(sig):
            return mime
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _engine_summary():
    """상태바 문구 — Qt의 engine_flags.summary()와 동일 형식(PySide6 의존 없이)."""
    pil = "Pillow ✓" if engine.PIL_AVAILABLE else "Pillow ✗"
    yara = "YARA ✓" if engine.YARA_ENGINE_AVAILABLE else "YARA ✗ (내장 정규식 폴백)"
    ole = "문서분석 ✓" if engine.docscan.OLEFILE_AVAILABLE else "문서분석 ✗"
    vba = "VBA ✓" if engine.docscan.OLEVBA_AVAILABLE else "VBA ✗"
    return f"엔진 준비   |   {pil}   |   {yara}   |   {ole}   |   {vba}   |   대상 파일은 실행하지 않습니다."


def _item_view(it):
    """탐지 항목 → 코드/Hex 뷰 텍스트, strings, 이미지 MIME, 다운로드용 base64 (Qt scan_tab._on_select와 같은 규칙)."""
    data = it.data or b""
    media = analysis.identify_buffer_media_type(data)
    is_text = (not media) and analysis.is_text_buffer(data, it.name)
    if it.decoded_text and len(it.decoded_text) <= 204800:
        view = it.decoded_text
    elif is_text and len(data) <= 204800:
        view = data.decode("utf-8", "replace")
    elif media:
        view = f"[이진 미디어 스트림: {media}]\n\n" + analysis.format_hex_dump(data[:4096])
    else:
        view = analysis.format_hex_dump(data[:8192])
    strs = engine.extract_strings(data, min_len=4)
    return {
        "id": it.id, "category": it.category, "format": it.format, "offset": it.offset,
        "size": it.size, "detail": it.detail, "name": it.name or f"item_{it.id}.bin",
        "view": view, "strings": strs[:4000],
        "mime": _raster_mime(data),
        "b64": base64.b64encode(data).decode("ascii") if len(data) <= MAX_ITEM_B64 else None,
    }


def _scan_payload(path, password):
    """파일 스캔 → 웹 화면이 쓰는 JSON 전체(판정·해시·항목·리포트·엔트로피·로그)."""
    t0 = time.time()
    lines = []
    r = engine.scan_file(path, password, log=lines.append)
    verdict, _ = engine._verdict(r)
    return {
        "filename": r.filename, "filesize": r.filesize, "carrier": r.carrier_fmt,
        "entropy": round(r.overall_entropy, 3), "natural_eof": r.natural_eof,
        "hashes": {"md5": r.md5, "sha1": r.sha1, "sha256": r.sha256},
        "verdict": verdict, "findings": list(r.findings),
        "items": [_item_view(it) for it in r.carved],
        "meta_report": r.meta_report,
        "entropy_blocks": analysis.entropy_blocks(r.file_bytes),
        "log": "\n".join(lines),
        "report_html": engine.build_report_html(r),
        "report_json": engine.build_report_json(r),
        "seconds": round(time.time() - t0, 1),
    }


def _b64file(data, name, info):
    return {"name": name, "b64": base64.b64encode(data).decode("ascii"), "info": info}


def _suffixed(name, suffix):
    base, ext = os.path.splitext(name)
    return f"{base}{suffix}{ext}"


class _Handler(BaseHTTPRequestHandler):
    server_version = "StegStudioWeb"

    def _send(self, code, body, ctype):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def _hdr(self, key, default=""):
        return urllib.parse.unquote(self.headers.get(key, default))

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            page = PAGE.replace("__VER__", __version__).replace("__STATUS__", _engine_summary())
            self._send(200, page, "text/html; charset=utf-8")
        elif self.path in ("/icon.png", "/favicon.ico"):
            with open(_ICON, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "max-age=86400")
            self.end_headers()
            self.wfile.write(data)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        routes = {"/api/scan": self._scan, "/api/cdr": self._cdr, "/api/meta": self._meta,
                  "/api/meta/edit": self._meta_edit, "/api/meta/scrub": self._meta_scrub}
        fn = routes.get(self.path)
        if not fn:
            return self._json(404, {"error": "not found"})
        size = int(self.headers.get("Content-Length") or 0)
        if size <= 0:
            return self._json(400, {"error": "빈 파일입니다."})
        if size > MAX_UPLOAD:
            return self._json(413, {"error": f"파일이 너무 큽니다 (최대 {MAX_UPLOAD // 1024 // 1024}MB)."})
        data = self.rfile.read(size)
        # 파일명은 확장자 판별·표시용으로만 사용 — 경로 성분 제거 + 안전 문자만 남김
        name = os.path.basename(self._hdr("X-Filename", "upload.bin").replace("\\", "/"))
        name = re.sub(r"[^\w.\-가-힣 ()]", "_", name).strip(" .") or "upload.bin"
        try:
            with tempfile.TemporaryDirectory(prefix="stegweb_") as tmp:
                path = os.path.join(tmp, name)
                with open(path, "wb") as f:
                    f.write(data)
                self._json(200, fn(path, name, data))
        except Exception as e:
            self._json(500, {"error": f"처리 실패: {e}"})

    # ---- 라우트 (모두 업로드 파일을 읽기만 하고, 결과 파일은 응답으로 돌려준다) ----
    def _scan(self, path, name, data):
        return _scan_payload(path, self._hdr("X-Password"))

    def _cdr(self, path, name, data):
        _, natural_eof = engine.identify_carrier_and_eof(data)
        out, info = engine.cdr_sanitize(data, path, natural_eof)
        return _b64file(out, _suffixed(name, "_cleaned"), info)

    def _meta(self, path, name, data):
        from . import metaedit
        fmt, rows, alerts = metaedit.inspect(data)
        return {"format": fmt, "rows": rows, "alerts": alerts}

    def _meta_edit(self, path, name, data):
        from . import metaedit
        changes = json.loads(self._hdr("X-Changes", "{}"))
        out, info = metaedit.edit(data, {str(k): str(v) for k, v in changes.items()})
        return _b64file(out, _suffixed(name, "_edited"), info)

    def _meta_scrub(self, path, name, data):
        from . import metaedit
        out, info = metaedit.scrub(data)
        return _b64file(out, _suffixed(name, "_scrubbed"), info)

    def log_message(self, fmt, *args):
        print(f"[web] {self.address_string()} {fmt % args}", flush=True)


def serve(host="127.0.0.1", port=DEFAULT_PORT):
    # ponytail: 단일 스레드 서버(한 번에 한 건 분석). 동시 사용자가 생기면 ThreadingHTTPServer + 엔진 스레드 안전성 점검
    httpd = HTTPServer((host, port), _Handler)
    import signal

    def _stop(*_):
        raise KeyboardInterrupt   # docker stop(SIGTERM)도 Ctrl+C처럼 즉시 정상 종료

    signal.signal(signal.SIGTERM, _stop)
    shown = "localhost" if host in ("0.0.0.0", "127.0.0.1") else host
    print(f"[+] 웹 UI 실행: http://{shown}:{port}  (종료: Ctrl+C)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


# =========================================================================
# 페이지 (Qt theme.py의 DARK/LIGHT 팔레트·QSS를 CSS로 옮김)
# =========================================================================
PAGE = r"""<!doctype html><html lang="ko" data-theme="dark"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>스테가노그래피·포렌식 보안 스튜디오</title><link rel="icon" href="/icon.png">
<style>
:root,[data-theme=dark]{--BASE:#1e1e2e;--MANTLE:#181825;--CRUST:#11111b;--S0:#313244;--S1:#45475a;--S2:#585b70;
 --TEXT:#cdd6f4;--SUB:#a6adc8;--BLUE:#89b4fa;--LAV:#b4befe;--GREEN:#a6e3a1;--RED:#f38ba8;--YEL:#f9e2af;--MAUVE:#cba6f7;--ON:#11111b}
[data-theme=light]{--BASE:#f4f4f8;--MANTLE:#ffffff;--CRUST:#ffffff;--S0:#e4e4ec;--S1:#d2d2dc;--S2:#b4b4c0;
 --TEXT:#1e1e2e;--SUB:#5c5f77;--BLUE:#1e66f5;--LAV:#5a6fd0;--GREEN:#40a02b;--RED:#d20f39;--YEL:#b8860b;--MAUVE:#8839ef;--ON:#ffffff}
*{box-sizing:border-box;font-family:'Malgun Gothic','Noto Sans KR',sans-serif;font-size:13.5px}
html,body{margin:0;background:var(--BASE);color:var(--TEXT)}
body{min-height:100vh;display:flex;flex-direction:column}
.mono,pre,textarea,table.grid td{font-family:Consolas,'D2Coding',monospace}
/* 탭 바 — QTabBar */
/* 헤더(페이지와 함께 스크롤 — 고정하지 않음): 앱 아이콘·이름 + 세그먼트형 탭 */
.wrap{width:100%;max-width:1600px;margin:0 auto;padding-left:20px;padding-right:20px}
header{background:var(--MANTLE);border-bottom:1px solid var(--S0)}
header .wrap{display:flex;align-items:center;justify-content:space-between;gap:18px;flex-wrap:wrap;padding-top:14px;padding-bottom:14px}
.brand{display:flex;align-items:center;gap:13px;min-width:0}
.brand img{width:42px;height:42px;border-radius:10px;flex:none}
.brand h1{margin:0;font-size:18px;font-weight:700;color:var(--TEXT);white-space:nowrap}
.brand p{margin:3px 0 0;color:var(--SUB);font-size:12px}
.tabbar{display:flex;gap:4px;padding:5px;background:var(--CRUST);border:1px solid var(--S0);border-radius:12px;overflow-x:auto;max-width:100%}
.tabbar button{display:flex;align-items:center;gap:7px;background:transparent;color:var(--SUB);padding:9px 16px;border:0;border-radius:8px;font-weight:600;cursor:pointer;white-space:nowrap;transition:background .15s,color .15s}
.tabbar button:hover:not(.on){background:var(--S0);color:var(--TEXT)}
.tabbar button.on{background:var(--BLUE);color:var(--ON);box-shadow:0 2px 8px rgba(0,0,0,.25)}
.tabbar .ic{font-size:15px;line-height:1}
main{flex:1;padding-top:14px;padding-bottom:20px}
section{display:none;flex-direction:column;gap:12px}
section.on{display:flex}
/* 그룹박스 — QGroupBox */
fieldset{border:1px solid var(--S0);border-radius:10px;margin:6px 0 0;padding:14px 20px 16px;min-width:0}
legend{color:var(--BLUE);font-weight:600;padding:0 6px;margin-left:6px}
.g{display:grid;gap:9px 10px;align-items:center}
label.l{white-space:nowrap}
input[type=text],input[type=password],select{width:100%;background:var(--CRUST);color:var(--TEXT);border:1px solid var(--S0);border-radius:8px;padding:8px 10px;outline:none}
input:focus,select:focus{border-color:var(--BLUE)}
button.b{background:var(--S0);color:var(--TEXT);border:0;border-radius:8px;padding:9px 16px;font-weight:600;cursor:pointer;white-space:nowrap}
button.b:hover{background:var(--S1)} button.b:active{background:var(--S2)}
button.b:disabled{background:var(--MANTLE);color:var(--S2);cursor:default}
button.accent{background:var(--BLUE);color:var(--ON)} button.accent:hover{background:var(--LAV)}
button.danger{background:var(--RED);color:var(--ON)} button.success{background:var(--GREEN);color:var(--ON)}
button.danger:disabled,button.success:disabled,button.accent:disabled{background:var(--MANTLE);color:var(--S2)}
.pick{cursor:pointer} .drop.over input{border-color:var(--BLUE);border-style:dashed}
.hint{color:var(--MAUVE)} .status{color:var(--TEXT);padding:2px 2px}
/* 표 — QTableView */
.tbl{border:1px solid var(--S0);border-radius:8px;overflow:auto;background:var(--MANTLE)}
table.grid{border-collapse:collapse;width:100%}
table.grid th{position:sticky;top:0;background:var(--S0);color:var(--BLUE);padding:7px;text-align:left;font-weight:600;white-space:nowrap}
table.grid td{padding:5px 7px;border-bottom:1px solid var(--S0);font-size:12px;vertical-align:top}
table.grid tr:nth-child(even) td{background:var(--BASE)}
table.grid tbody tr{cursor:pointer} table.grid tbody tr.sel td{background:var(--S1)}
pre,textarea{margin:0;background:var(--CRUST);color:var(--TEXT);border:1px solid var(--S0);border-radius:8px;padding:8px 10px;white-space:pre-wrap;word-break:break-all;overflow:auto;font-size:12.5px}
/* 스캐너 하단 분할 */
.split{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px;height:clamp(560px,78vh,880px)}
.col{display:flex;flex-direction:column;gap:6px;min-height:0}
.col fieldset{display:flex;flex-direction:column;min-height:0}
.col fieldset pre{min-height:0}
/* 상세 분석 뷰어 — 헤더 탭과 같은 세그먼트형, 한 줄(좁으면 가로 스크롤) */
.seg{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:3px;padding:4px;background:var(--CRUST);border:1px solid var(--S0);border-radius:10px;flex:none}
.seg button{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;min-width:0;background:transparent;color:var(--SUB);padding:6px 2px;border:0;border-radius:7px;font-weight:600;font-size:12px;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;transition:background .15s,color .15s}
.seg .ic{font-size:16px;line-height:1}
.seg button:hover:not(.on){background:var(--S0);color:var(--TEXT)}
.seg button.on{background:var(--BLUE);color:var(--ON)}
.pane{display:none;flex:1;min-height:0;margin-top:8px;border:1px solid var(--S0);border-radius:8px;background:var(--CRUST);overflow:auto}
.pane.on{display:block} .pane pre{border:0;border-radius:0;min-height:100%}
.pane .row{border-bottom:1px solid var(--S0)}
.ph{color:var(--S2);padding:30px;text-align:center}
.imgbox{padding:10px;text-align:center} .imgbox img{width:max(240px,40%);max-width:100%;image-rendering:pixelated;border:1px solid var(--S0)}
.verdict{display:inline-block;padding:1px 8px;border-radius:6px;font-weight:700;color:var(--ON)}
.v-의심{background:var(--RED)} .v-참고{background:var(--YEL)} .v-정상{background:var(--GREEN)}
.statusbar{background:var(--MANTLE);color:var(--SUB);padding:5px 10px;font-size:12.5px;border-top:1px solid var(--S0);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
progress{width:100%;height:4px;appearance:none;border:0;background:var(--S0)} progress::-webkit-progress-bar{background:var(--S0)} progress::-webkit-progress-value{background:var(--BLUE)}
dialog{background:var(--MANTLE);color:var(--TEXT);border:1px solid var(--S0);border-radius:10px;max-width:90vw;max-height:90vh}
@media (max-width:900px){.split{grid-template-columns:1fr}}
</style></head><body>
<header><div class="wrap">
 <div class="brand"><img src="/icon.png" alt="">
  <div><h1>스테가노그래피·포렌식 보안 스튜디오</h1><p>Stego &amp; Forensic Security Studio · v__VER__ · 웹 UI</p></div></div>
 <nav class="tabbar" id="tabbar">
  <button data-t="scan" class="on"><span class="ic">🔍</span>정밀 포렌식 스캐너</button>
  <button data-t="batch"><span class="ic">📁</span>디렉터리 일괄 스캔</button>
  <button data-t="meta"><span class="ic">🏷️</span>메타데이터</button>
  <button data-t="settings"><span class="ic">⚙️</span>설정</button>
 </nav>
</div></header>
<main class="wrap">
<!-- ===================== 정밀 포렌식 스캐너 ===================== -->
<section id="t-scan" class="on">
 <fieldset class="drop" id="scanDrop"><legend>검사 대상 및 보안 조치</legend>
  <div class="g" style="grid-template-columns:auto 1fr auto 260px">
   <label class="l">검사 파일:</label><input type="text" id="sPath" class="pick" readonly placeholder="파일을 끌어다 놓거나 [찾아보기]">
   <button class="b" id="sBrowse">찾아보기</button><button class="b accent" id="sScan" disabled>정밀 포렌식 스캔</button>
   <label class="l">복호화 비밀번호:</label><input type="password" id="sPw" autocomplete="off">
   <span></span><button class="b danger" id="sExtract" disabled>선택 항목 추출 저장</button>
   <div class="row" style="grid-column:1/3"><button class="b" id="sHtml" disabled>HTML 리포트 저장</button><button class="b" id="sJson" disabled>JSON 리포트 저장</button>
     <span class="hint">🐳 컨테이너 격리 환경에서 실행 중 — 업로드 파일은 실행되지 않습니다.</span></div>
   <span></span><button class="b success" id="sCdr" disabled>안전 재구성 / 후미 절단 저장 (CDR)</button>
  </div>
  <input type="file" id="sFile" hidden>
 </fieldset>
 <fieldset><legend>파일 해시</legend>
  <div class="g" style="grid-template-columns:auto 1fr auto">
   <label class="l">MD5:</label><input type="text" id="hMd5" class="mono" readonly><button class="b" data-copy="hMd5">복사</button>
   <label class="l">SHA-1:</label><input type="text" id="hSha1" class="mono" readonly><button class="b" data-copy="hSha1">복사</button>
   <label class="l">SHA-256:</label><input type="text" id="hSha256" class="mono" readonly><button class="b" data-copy="hSha256">복사</button>
  </div>
 </fieldset>
 <progress id="sProg" hidden></progress>
 <div class="split">
  <div class="col">
   <fieldset style="flex:0 0 220px"><legend>탐지된 은닉 파일 / 미디어 / 코드 목록</legend>
    <div class="tbl" style="flex:1"><table class="grid"><thead><tr><th>#</th><th>기법</th><th>포맷/언어</th><th>오프셋</th><th>크기(B)</th><th>세부</th></tr></thead><tbody id="sItems"></tbody></table></div>
   </fieldset>
   <fieldset style="flex:1"><legend>통합 포렌식 스캔 리포트</legend><pre id="sLog" style="flex:1"></pre></fieldset>
  </div>
  <div class="col">
   <fieldset style="flex:1"><legend>상세 분석 뷰어</legend>
   <div class="seg" id="insp">
    <button data-p="code" class="on" title="코드 / Hex 뷰어"><span class="ic">📄</span>코드·Hex</button><button data-p="img" title="이미지 뷰어"><span class="ic">🖼️</span>이미지</button>
    <button data-p="meta" title="메타데이터 / 청크"><span class="ic">🧩</span>메타·청크</button><button data-p="bit" title="비트 평면"><span class="ic">🔬</span>비트 평면</button>
    <button data-p="ent" title="엔트로피 차트"><span class="ic">📈</span>엔트로피</button><button data-p="str" title="문자열(strings)"><span class="ic">🔤</span>문자열</button><button data-p="rep" title="분석 리포트"><span class="ic">📑</span>리포트</button>
   </div>
   <div class="pane on" id="p-code"><pre id="vCode"></pre></div>
   <div class="pane" id="p-img"><div class="imgbox" id="vImg"><div class="ph">은닉 이미지가 탐지되면 여기에 표시됩니다.</div></div></div>
   <div class="pane" id="p-meta"><pre id="vMeta"></pre></div>
   <div class="pane" id="p-bit"><div class="row" style="padding:8px">채널: <select id="bpCh" style="width:auto"><option>Red (R)</option><option>Green (G)</option><option>Blue (B)</option><option>Grayscale</option></select>
     비트: <select id="bpBit" style="width:auto"></select></div><div class="imgbox" id="vBit"><div class="ph">이미지 파일을 스캔하면 비트 평면이 표시됩니다.</div></div></div>
   <div class="pane" id="p-ent"><canvas id="vEnt" style="width:100%;height:100%;display:block"></canvas></div>
   <div class="pane" id="p-str"><pre id="vStr"></pre></div>
   <div class="pane" id="p-rep"><iframe id="vRep" sandbox title="분석 리포트" style="width:100%;height:100%;border:0;background:#1e1e2e;display:block"></iframe></div>
   </fieldset>
  </div>
 </div>
 <div class="status" id="sStatus">파일을 선택하고 [정밀 포렌식 스캔]을 누르세요.</div>
</section>
<!-- ===================== 디렉터리 일괄 스캔 ===================== -->
<section id="t-batch">
 <fieldset><legend>디렉터리 일괄 보안 스캔</legend>
  <div class="g" style="grid-template-columns:auto 1fr auto auto auto">
   <label class="l">대상 폴더:</label><input type="text" id="bPath" readonly placeholder="폴더 또는 여러 파일 선택">
   <button class="b" id="bDir">폴더 선택</button><button class="b" id="bFiles">파일 선택</button><button class="b accent" id="bRun" disabled>일괄 스캔 시작</button>
  </div>
  <input type="file" id="bDirIn" webkitdirectory multiple hidden><input type="file" id="bFileIn" multiple hidden>
 </fieldset>
 <div class="hint" id="bStatus">폴더를 선택하고 [일괄 스캔 시작]을 누르세요. (하위 폴더 포함)</div>
 <progress id="bProg" hidden value="0"></progress>
 <div class="tbl" style="flex:1;min-height:420px"><table class="grid"><thead><tr><th>#</th><th>판정</th><th>파일명</th><th>포맷</th><th>크기(B)</th><th>탐지 요약</th></tr></thead><tbody id="bRows"></tbody></table></div>
 <div class="row"><button class="b" id="bCsv" disabled>CSV 리포트 저장</button><button class="b" id="bHtml" disabled>HTML 리포트 저장</button></div>
 <div class="hint">행 더블클릭 → 스캐너 탭에서 열기.</div>
</section>
<!-- ===================== 메타데이터 ===================== -->
<section id="t-meta">
 <fieldset class="drop" id="mDrop"><legend>메타데이터 편집 / 삭제</legend>
  <div class="g" style="grid-template-columns:auto 1fr auto"><label class="l">파일:</label><input type="text" id="mPath" class="pick" readonly placeholder="파일을 끌어다 놓거나 [파일 열기]"><button class="b" id="mOpen">파일 열기</button></div>
  <input type="file" id="mFile" hidden>
 </fieldset>
 <div class="hint" id="mStatus">파일을 열면 메타데이터가 표시됩니다. 값 칸을 클릭해 편집하세요.</div>
 <div class="tbl" style="flex:1;min-height:420px"><table class="grid"><thead><tr><th style="width:35%">키</th><th>값 (편집 가능)</th></tr></thead><tbody id="mRows"></tbody></table></div>
 <div class="row"><button class="b accent" id="mSave" disabled>변경 저장</button><button class="b" id="mScrub" disabled>전체 삭제(스크럽) 저장</button></div>
</section>
<!-- ===================== 설정 ===================== -->
<section id="t-settings">
 <fieldset><legend>외관</legend><div class="g" style="grid-template-columns:auto 1fr"><label class="l">테마:</label>
  <select id="theme"><option value="dark">다크 모드</option><option value="light">화이트 모드</option></select></div></fieldset>
 <fieldset><legend>스캔 · 격리</legend><div class="g" style="grid-template-columns:auto 1fr">
  <label class="l">실행 환경:</label><span>웹 서버(도커 컨테이너) — 업로드 파일은 임시 폴더에서 분석 후 즉시 삭제, 실행하지 않음</span>
  <label class="l">업로드 상한:</label><span>100 MB</span>
  <label class="l">엔진 상태:</label><span class="mono">__STATUS__</span>
  <label class="l">버전:</label><span>v__VER__</span></div></fieldset>
 <div class="hint">테마는 이 브라우저에 저장됩니다.</div>
</section>
</main>
<footer class="statusbar"><div class="wrap" style="padding-top:0;padding-bottom:0">__STATUS__</div></footer>
<script>
const $=id=>document.getElementById(id);
const fmt=n=>n.toLocaleString();
function el(tag,text,cls){const e=document.createElement(tag);if(text!=null)e.textContent=text;if(cls)e.className=cls;return e}
function download(name,blob){const a=el('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),5000)}
function b64blob(b64,type){const s=atob(b64),u=new Uint8Array(s.length);for(let i=0;i<s.length;i++)u[i]=s.charCodeAt(i);return new Blob([u],{type:type||'application/octet-stream'})}
async function post(url,file,headers={}){
  const r=await fetch(url,{method:'POST',body:file,headers:Object.assign({'X-Filename':encodeURIComponent(file.name)},headers)});
  let d;try{d=await r.json()}catch{throw new Error('서버 응답 오류 ('+r.status+')')}
  if(!r.ok)throw new Error(d.error||r.status);return d}
// 상위 탭 / 검사 결과 서브탭
$('tabbar').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;
  [...$('tabbar').children].forEach(x=>x.classList.toggle('on',x===b));
  document.querySelectorAll('main>section').forEach(s=>s.classList.toggle('on',s.id==='t-'+b.dataset.t))});
$('insp').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;
  [...$('insp').children].forEach(x=>x.classList.toggle('on',x===b));
  document.querySelectorAll('.pane').forEach(p=>p.classList.toggle('on',p.id==='p-'+b.dataset.p));
  if(b.dataset.p==='ent')drawEntropy()});
function showPane(p){$('insp').querySelector(`[data-p=${p}]`).click()}
// 파일 선택(클릭/찾아보기/드래그앤드롭) 공용
function filePicker(drop,input,pathEl,btns,onPick){
  const pick=f=>{if(!f)return;pathEl.value=f.name+'  ('+fmt(f.size)+' bytes)';onPick(f)};
  [pathEl,...btns].forEach(b=>b.onclick=()=>input.click()); input.onchange=e=>pick(e.target.files[0]);
  drop.ondragover=e=>{e.preventDefault();drop.classList.add('over')}; drop.ondragleave=()=>drop.classList.remove('over');
  drop.ondrop=e=>{e.preventDefault();drop.classList.remove('over');pick(e.dataTransfer.files[0])}}
// 테마
function setTheme(t){document.documentElement.dataset.theme=t;$('theme').value=t;try{localStorage.setItem('stegTheme',t)}catch{} drawEntropy()}
$('theme').onchange=e=>setTheme(e.target.value);
try{setTheme(localStorage.getItem('stegTheme')||'dark')}catch{setTheme('dark')}

/* ===================== 정밀 포렌식 스캐너 ===================== */
let sFileObj=null,S=null,selItem=null;
for(let i=0;i<8;i++)$('bpBit').append(el('option','Bit '+i+(i===0?' (LSB)':i===7?' (MSB)':'')));
filePicker($('scanDrop'),$('sFile'),$('sPath'),[$('sBrowse')],f=>{sFileObj=f;$('sScan').disabled=false});
$('sScan').onclick=()=>runScan(sFileObj);
async function runScan(f){
  if(!f)return; sFileObj=f; $('sPath').value=f.name+'  ('+fmt(f.size)+' bytes)';
  ['sScan','sExtract','sCdr','sHtml','sJson'].forEach(i=>$(i).disabled=true);
  $('sProg').hidden=false; $('sStatus').textContent='스캔 중…'; $('sLog').textContent='';
  try{ S=await post('/api/scan',f,{'X-Password':encodeURIComponent($('sPw').value)}); S.file=f; renderScan(); }
  catch(e){ $('sStatus').textContent='스캔 실패 — '+e.message; }
  $('sProg').hidden=true; $('sScan').disabled=false;
}
function renderScan(){
  $('hMd5').value=S.hashes.md5;$('hSha1').value=S.hashes.sha1;$('hSha256').value=S.hashes.sha256;
  $('sLog').textContent=S.log; $('sLog').scrollTop=$('sLog').scrollHeight;
  $('vMeta').textContent=S.meta_report||'(메타데이터/청크 정보 없음)';
  $('vRep').srcdoc=S.report_html;
  const tb=$('sItems'); tb.replaceChildren();
  S.items.forEach(it=>{const tr=el('tr');[it.id,it.category,it.format,it.offset,fmt(it.size),it.detail].forEach(v=>tr.append(el('td',String(v))));
    tr.onclick=()=>selectItem(it,tr); tb.append(tr)});
  ['sCdr','sHtml','sJson'].forEach(i=>$(i).disabled=false);
  const crit=S.findings.filter(f=>f.includes('CRITICAL')||f.includes('HIGH')).length;
  const v=el('span',S.verdict,'verdict v-'+S.verdict);
  $('sStatus').replaceChildren(v,document.createTextNode(S.items.length?`  스캔 완료 — 탐지 항목 ${S.items.length}개, 주요 경보 ${crit}건 (${S.seconds}초)`:`  스캔 완료 — 탐지 항목 없음 (경보 ${S.findings.length}건은 리포트 참고, ${S.seconds}초)`));
  if(S.items.length) selectItem(S.items[0],tb.firstChild);
  else{ selItem=null; $('vCode').textContent='탐지 항목이 없습니다.'; $('vStr').textContent=''; $('vImg').replaceChildren(el('div','은닉 이미지가 탐지되면 여기에 표시됩니다.','ph')); }
  renderBitplane(); drawEntropy();
}
function selectItem(it,tr){
  selItem=it; [...$('sItems').children].forEach(r=>r.classList.toggle('sel',r===tr)); $('sExtract').disabled=!it.b64;
  $('vCode').textContent=it.view;
  $('vStr').textContent=it.strings.length?`[출력 가능 문자열 ${it.strings.length}개 (최소 4자)]\n\n`+it.strings.join('\n'):'추출된 문자열이 없습니다.';
  if(it.mime&&it.b64){const img=el('img');img.src='data:'+it.mime+';base64,'+it.b64;img.alt=it.name;$('vImg').replaceChildren(img)}
  else $('vImg').replaceChildren(el('div','이 항목은 이미지가 아닙니다. [코드/Hex 뷰어]를 확인하세요.','ph'));
}
$('sExtract').onclick=()=>selItem&&selItem.b64&&download(selItem.name,b64blob(selItem.b64));
$('sHtml').onclick=()=>download(S.filename.replace(/\.[^.]*$/,'')+'_report.html',new Blob([S.report_html],{type:'text/html'}));
$('sJson').onclick=()=>download(S.filename.replace(/\.[^.]*$/,'')+'_report.json',new Blob([S.report_json],{type:'application/json'}));
$('sCdr').onclick=async()=>{ try{const d=await post('/api/cdr',S.file);download(d.name,b64blob(d.b64));$('sStatus').textContent='CDR 완료 — '+d.info}catch(e){$('sStatus').textContent='CDR 오류 — '+e.message} };
document.querySelectorAll('[data-copy]').forEach(b=>b.onclick=()=>{const v=$(b.dataset.copy).value;if(!v)return;
  (navigator.clipboard?navigator.clipboard.writeText(v):Promise.reject()).catch(()=>{$(b.dataset.copy).select();document.execCommand('copy')});
  b.textContent='복사됨';setTimeout(()=>b.textContent='복사',1200)});
// 비트 평면 — 브라우저 캔버스에서 계산(원본 이미지 파일 기준, Qt _render_bitplane과 동일 의미)
$('bpCh').onchange=$('bpBit').onchange=renderBitplane;
function renderBitplane(){
  const box=$('vBit'); if(!S||!S.file){return}
  if(!/\.(png|bmp|jpe?g|webp|gif)$/i.test(S.file.name)){box.replaceChildren(el('div','현재 대상은 이미지가 아니므로 비트 평면을 지원하지 않습니다.','ph'));return}
  const img=new Image(); img.onload=()=>{const c=el('canvas');c.width=img.naturalWidth;c.height=img.naturalHeight;const x=c.getContext('2d');x.drawImage(img,0,0);
    const d=x.getImageData(0,0,c.width,c.height),p=d.data,ch=$('bpCh').selectedIndex,bit=$('bpBit').selectedIndex;
    for(let i=0;i<p.length;i+=4){const v=ch===3?Math.round((p[i]*299+p[i+1]*587+p[i+2]*114)/1000):p[i+ch];const o=((v>>bit)&1)*255;p[i]=p[i+1]=p[i+2]=o;p[i+3]=255}
    x.putImageData(d,0,0);c.style.cssText='width:max(240px,40%);max-width:100%;image-rendering:pixelated;border:1px solid var(--S0)';box.replaceChildren(c);URL.revokeObjectURL(img.src)};
  img.onerror=()=>box.replaceChildren(el('div','브라우저에서 이 이미지를 디코딩할 수 없습니다.','ph'));
  img.src=URL.createObjectURL(S.file);
}
// 엔트로피 차트 — Qt EntropyChart와 같은 구성(0~8 격자, 7.5 임계선, 정상 종료지점 표시)
function drawEntropy(){
  const c=$('vEnt'); if(!c||!c.offsetWidth)return; const css=getComputedStyle(document.documentElement),V=k=>css.getPropertyValue(k).trim();
  const dpr=window.devicePixelRatio||1,w=c.offsetWidth,h=Math.max(c.offsetHeight,320); c.width=w*dpr;c.height=h*dpr; const g=c.getContext('2d');g.scale(dpr,dpr);
  g.fillStyle=V('--CRUST');g.fillRect(0,0,w,h); const L=48,R=20,T=24,B=36,pw=w-L-R,ph=h-T-B; g.font='11px Consolas,monospace';
  for(const v of [0,2,4,6,8]){const y=T+ph-v/8*ph;g.strokeStyle=V('--S0');g.setLineDash([4,4]);g.beginPath();g.moveTo(L,y);g.lineTo(L+pw,y);g.stroke();g.setLineDash([]);g.fillStyle=V('--SUB');g.textAlign='right';g.fillText(v.toFixed(1),L-6,y+4)}
  if(!S||!S.entropy_blocks.length){g.fillStyle=V('--S2');g.textAlign='center';g.fillText('스캔하면 블록별 엔트로피 분포가 표시됩니다.',w/2,h/2);return}
  const bl=S.entropy_blocks,bw=pw/bl.length; const y75=T+ph-7.5/8*ph;
  bl.forEach((e,i)=>{const bh=e/8*ph;g.fillStyle=e>=7.5?V('--RED'):e>=6?V('--YEL'):V('--BLUE');g.fillRect(L+i*bw+1,T+ph-bh,Math.max(bw-2,1),bh)});
  g.strokeStyle=V('--RED');g.setLineDash([6,4]);g.beginPath();g.moveTo(L,y75);g.lineTo(L+pw,y75);g.stroke();g.setLineDash([]);
  g.fillStyle=V('--RED');g.textAlign='left';g.fillText('7.5 (암호화/압축 의심)',L+6,y75-6);
  if(S.natural_eof&&S.natural_eof<S.filesize){const x=L+S.natural_eof/S.filesize*pw;g.strokeStyle=V('--GREEN');g.beginPath();g.moveTo(x,T);g.lineTo(x,T+ph);g.stroke();g.fillStyle=V('--GREEN');g.fillText('정상 종료지점 0x'+S.natural_eof.toString(16).toUpperCase(),Math.min(x+4,w-160),T+12)}
  g.fillStyle=V('--SUB');g.textAlign='center';g.fillText(`파일 오프셋 → (블록 ${bl.length}개, 전체 ${fmt(S.filesize)} B, 평균 엔트로피 ${S.entropy})`,L+pw/2,h-12);
}
window.addEventListener('resize',drawEntropy);

/* ===================== 디렉터리 일괄 스캔 ===================== */
let bList=[],bResults=[],bBusy=false,bCancel=false;
$('bDir').onclick=()=>$('bDirIn').click(); $('bFiles').onclick=()=>$('bFileIn').click(); $('bPath').onclick=()=>$('bDirIn').click();
function bPick(files){bList=[...files].filter(f=>f.size>0);
  const root=bList[0]&&bList[0].webkitRelativePath?bList[0].webkitRelativePath.split('/')[0]+'/':'선택한 파일';
  $('bPath').value=`${root}  (${bList.length}개 파일)`;$('bRun').disabled=!bList.length;$('bStatus').textContent=`${bList.length}개 파일 준비됨 — [일괄 스캔 시작]을 누르세요.`}
$('bDirIn').onchange=e=>bPick(e.target.files); $('bFileIn').onchange=e=>bPick(e.target.files);
$('bRun').onclick=async()=>{
  if(bBusy){bCancel=true;$('bStatus').textContent='취소 중… (진행 중인 파일 끝나면 중단)';return}
  bBusy=true;bCancel=false;bResults=[];$('bRows').replaceChildren();$('bRun').textContent='취소';$('bCsv').disabled=$('bHtml').disabled=true;
  const pg=$('bProg');pg.hidden=false;pg.max=bList.length;pg.value=0; let sus=0;
  for(const [i,f] of bList.entries()){ if(bCancel)break;
    $('bStatus').textContent=`[${i+1}/${bList.length}] ${f.webkitRelativePath||f.name} 스캔 중…`;
    let row; try{const d=await post('/api/scan',f);d.file=f;row={n:i+1,verdict:d.verdict,name:f.webkitRelativePath||f.name,fmt:d.carrier,size:d.filesize,summary:d.findings[0]||'특이사항 없음',data:d}}
    catch(e){row={n:i+1,verdict:'오류',name:f.webkitRelativePath||f.name,fmt:'-',size:f.size,summary:e.message,data:null}}
    if(row.verdict==='의심')sus++; bResults.push(row);
    const tr=el('tr');const vc=el('td');vc.append(el('span',row.verdict,'verdict v-'+row.verdict));
    tr.append(el('td',String(row.n)),vc,el('td',row.name),el('td',row.fmt),el('td',fmt(row.size)),el('td',row.summary));
    tr.ondblclick=()=>{if(!row.data)return;S=row.data;$('tabbar').children[0].click();$('sPath').value=row.name+'  ('+fmt(row.size)+' bytes)';sFileObj=row.data.file;$('sScan').disabled=false;renderScan()};
    tr.onclick=()=>[...$('bRows').children].forEach(r=>r.classList.toggle('sel',r===tr));
    $('bRows').append(tr); pg.value=i+1;
  }
  $('bStatus').textContent=`${bCancel?'취소됨':'완료'} — ${bResults.length}개 검사, 의심 ${sus}개`;
  pg.hidden=true;$('bRun').textContent='일괄 스캔 시작';bBusy=false;$('bCsv').disabled=$('bHtml').disabled=!bResults.length;
};
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
$('bCsv').onclick=()=>{const q=s=>'"'+String(s).replace(/"/g,'""')+'"';
  const lines=[['#','판정','파일명','포맷','크기(B)','탐지 요약','SHA-256'].map(q).join(',')].concat(bResults.map(r=>[r.n,r.verdict,r.name,r.fmt,r.size,r.data?r.data.findings.join(' | ')||'특이사항 없음':r.summary,r.data?r.data.hashes.sha256:''].map(q).join(',')));
  download('batch_report.csv',new Blob(['﻿'+lines.join('\r\n')],{type:'text/csv'}))};
$('bHtml').onclick=()=>{const rows=bResults.map(r=>`<tr><td>${r.n}</td><td>${esc(r.verdict)}</td><td>${esc(r.name)}</td><td>${esc(r.fmt)}</td><td>${fmt(r.size)}</td><td>${esc(r.data?r.data.findings.join('\n')||'특이사항 없음':r.summary).replace(/\n/g,'<br>')}</td></tr>`).join('');
  download('batch_report.html',new Blob([`<!doctype html><html lang="ko"><meta charset="utf-8"><title>일괄 스캔 리포트</title><style>body{font-family:'Malgun Gothic',sans-serif;background:#1e1e2e;color:#cdd6f4;padding:24px}h1{color:#89b4fa}table{border-collapse:collapse;width:100%}th,td{border:1px solid #313244;padding:6px 8px;font-size:13px;text-align:left;vertical-align:top}th{background:#313244;color:#89b4fa}</style><h1>디렉터리 일괄 스캔 리포트</h1><p>${bResults.length}개 파일 · 의심 ${bResults.filter(r=>r.verdict==='의심').length}개</p><table><tr><th>#</th><th>판정</th><th>파일명</th><th>포맷</th><th>크기(B)</th><th>탐지 요약</th></tr>${rows}</table></html>`],{type:'text/html'}))};

/* ===================== 메타데이터 ===================== */
let mFileObj=null,mOrig={};
filePicker($('mDrop'),$('mFile'),$('mPath'),[$('mOpen')],loadMeta);
async function loadMeta(f){
  mFileObj=f;$('mStatus').textContent='메타데이터 읽는 중…';$('mRows').replaceChildren();$('mSave').disabled=$('mScrub').disabled=true;
  try{const d=await post('/api/meta',f);mOrig={};
    d.rows.forEach(([k,v])=>{mOrig[k]=String(v);const tr=el('tr'),td=el('td');const inp=el('input');inp.type='text';inp.value=String(v);inp.dataset.k=k;
      inp.style.cssText='border:0;background:transparent;padding:2px 0;font-family:inherit;font-size:12px';td.append(inp);tr.append(el('td',k),td);$('mRows').append(tr)});
    $('mStatus').textContent=`포맷: ${d.format} · 메타데이터 ${d.rows.length}개`+(d.alerts.length?'  |  ⚠ '+d.alerts.join(' / '):'')+'  — 값 칸을 클릭해 편집, 비우면 해당 필드 삭제.';
    $('mSave').disabled=!d.rows.length;$('mScrub').disabled=false}
  catch(e){$('mStatus').textContent='읽기 실패 — '+e.message}
}
$('mSave').onclick=async()=>{const ch={};document.querySelectorAll('#mRows input').forEach(i=>{if(i.value!==mOrig[i.dataset.k])ch[i.dataset.k]=i.value});
  if(!Object.keys(ch).length){$('mStatus').textContent='변경된 값이 없습니다.';return}
  try{const d=await post('/api/meta/edit',mFileObj,{'X-Changes':encodeURIComponent(JSON.stringify(ch))});download(d.name,b64blob(d.b64));$('mStatus').textContent='저장 완료 — '+d.info}catch(e){$('mStatus').textContent='편집 실패 — '+e.message}};
$('mScrub').onclick=async()=>{try{const d=await post('/api/meta/scrub',mFileObj);download(d.name,b64blob(d.b64));$('mStatus').textContent='스크럽 완료 — '+d.info}catch(e){$('mStatus').textContent='스크럽 실패 — '+e.message}};
</script></body></html>"""
