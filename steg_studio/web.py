"""
웹 UI — 브라우저에서 파일 업로드 → 포렌식 스캔 → 리포트 확인. 표준 라이브러리(http.server)만 사용.

도커 컨테이너처럼 화면이 없는 환경에서 GUI 대신 쓴다.
    python -m steg_studio web                      (http://127.0.0.1:47821)
    docker run --rm -p 127.0.0.1:47821:47821 steg-studio web --host 0.0.0.0

안전 원칙: 업로드 파일은 임시 폴더에 저장해 '분석만' 하고 절대 실행하지 않으며, 응답 직후 삭제한다.
리포트는 스크립트가 막힌 sandbox iframe에, 로그는 textContent로만 표시(업로드 내용이 HTML로 해석되지 않게).
"""

import os
import re
import json
import tempfile
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

from . import engine, __version__

DEFAULT_PORT = 47821
MAX_UPLOAD = 100 * 1024 * 1024   # 업로드 상한 100MB (엔진 상한 256MB보다 작게: 시연·메모리 여유)

PAGE = """<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Stego Studio</title>
<style>
:root{--bg:#1e1e2e;--panel:#181825;--line:#313244;--fg:#cdd6f4;--dim:#a6adc8;--acc:#89b4fa;--bad:#f38ba8;--warn:#fab387;--ok:#a6e3a1}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:'Malgun Gothic','Noto Sans KR',sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 16px}
h1{margin:0 0 4px;color:var(--acc);font-size:24px} .sub{color:var(--dim);margin:0 0 22px;font-size:14px}
#drop{border:2px dashed var(--line);border-radius:12px;padding:34px 16px;text-align:center;background:var(--panel);cursor:pointer;transition:border-color .15s}
#drop.over,#drop:hover{border-color:var(--acc)} #drop b{color:var(--acc)} #fname{margin-top:8px;color:var(--ok);font-size:14px;word-break:break-all}
.row{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}
input[type=password]{flex:1;min-width:200px;padding:11px 12px;border-radius:8px;border:1px solid var(--line);background:var(--panel);color:var(--fg);font-size:14px}
button{padding:11px 26px;border:0;border-radius:8px;background:var(--acc);color:#11111b;font-weight:700;font-size:15px;cursor:pointer}
button:disabled{opacity:.5;cursor:wait}
#status{margin-top:14px;min-height:22px;color:var(--dim)}
#verdict{display:none;margin-top:18px;padding:16px 18px;border-radius:10px;background:var(--panel);border-left:6px solid var(--ok)}
#verdict.bad{border-color:var(--bad)} #verdict.warn{border-color:var(--warn)}
#verdict h2{margin:0 0 8px;font-size:20px} #verdict ul{margin:0;padding-left:20px;font-size:14px;line-height:1.6}
iframe{display:none;width:100%;height:900px;margin-top:18px;border:1px solid var(--line);border-radius:10px;background:#1e1e2e}
details{margin-top:14px} summary{cursor:pointer;color:var(--acc)}
pre{background:#11111b;padding:12px;border-radius:8px;font-size:12px;max-height:500px;overflow:auto;white-space:pre-wrap;word-break:break-all}
</style></head><body><main>
<h1>Stego &amp; Forensic Security Studio</h1>
<p class="sub">파일을 올리면 숨겨진 데이터·스테가노그래피·악성 코드 흔적을 분석합니다. 업로드 파일은 실행되지 않으며 분석 후 즉시 삭제됩니다. (v__VER__)</p>
<div id="drop"><input id="file" type="file" hidden>
  <div><b>파일을 끌어다 놓거나 클릭해서 선택</b></div><div id="fname"></div></div>
<div class="row"><input id="pw" type="password" placeholder="암호화 패킷 비밀번호 (선택)" autocomplete="off">
  <button id="go" disabled>검사</button></div>
<div id="status"></div>
<div id="verdict"><h2 id="vtitle"></h2><ul id="vlist"></ul></div>
<iframe id="report" sandbox title="분석 리포트"></iframe>
<details id="logbox" hidden><summary>상세 분석 로그</summary><pre id="log"></pre></details>
</main><script>
const $=id=>document.getElementById(id); let picked=null;
function pick(f){picked=f;$('fname').textContent=f?f.name+' ('+f.size.toLocaleString()+' bytes)':'';$('go').disabled=!f}
$('drop').onclick=()=>$('file').click(); $('file').onchange=e=>pick(e.target.files[0]);
$('drop').ondragover=e=>{e.preventDefault();$('drop').classList.add('over')};
$('drop').ondragleave=()=>$('drop').classList.remove('over');
$('drop').ondrop=e=>{e.preventDefault();$('drop').classList.remove('over');pick(e.dataTransfer.files[0])};
$('go').onclick=async()=>{
  $('go').disabled=true;$('status').textContent='분석 중… (파일 크기에 따라 수십 초 걸릴 수 있음)';
  ['verdict','report'].forEach(i=>$(i).style.display='none');$('logbox').hidden=true;
  try{
    const r=await fetch('/scan',{method:'POST',body:picked,headers:{'X-Filename':encodeURIComponent(picked.name),'X-Password':encodeURIComponent($('pw').value)}});
    const d=await r.json(); if(!r.ok) throw new Error(d.error||r.status);
    const v=$('verdict'); v.className=d.verdict==='의심'?'bad':d.verdict==='참고'?'warn':'';
    $('vtitle').textContent='판정: '+d.verdict+' — 탐지 항목 '+d.carved+'개 / 판정 '+d.findings.length+'건';
    $('vlist').replaceChildren(...(d.findings.length?d.findings:['특이사항 없음']).map(t=>{const li=document.createElement('li');li.textContent=t;return li}));
    v.style.display='block'; $('report').srcdoc=d.report_html; $('report').style.display='block';
    $('log').textContent=d.log; $('logbox').hidden=false; $('status').textContent='완료 ('+d.seconds+'초)';
  }catch(e){$('status').textContent='오류: '+e.message}
  $('go').disabled=false;
};
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "StegStudioWeb"

    def _send(self, code, body, ctype):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE.replace("__VER__", __version__), "text/html; charset=utf-8")
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/scan":
            return self._json(404, {"error": "not found"})
        size = int(self.headers.get("Content-Length") or 0)
        if size <= 0:
            return self._json(400, {"error": "빈 파일입니다."})
        if size > MAX_UPLOAD:
            return self._json(413, {"error": f"파일이 너무 큽니다 (최대 {MAX_UPLOAD // 1024 // 1024}MB)."})
        data = self.rfile.read(size)
        # 파일명은 확장자 판별용으로만 사용 — 경로 성분 제거 + 안전 문자만 남김
        name = os.path.basename(urllib.parse.unquote(self.headers.get("X-Filename", "upload.bin")))
        name = re.sub(r"[^\w.\-가-힣 ]", "_", name).strip(" .") or "upload.bin"
        password = urllib.parse.unquote(self.headers.get("X-Password", ""))

        import time
        t0 = time.time()
        lines = []
        with tempfile.TemporaryDirectory(prefix="stegweb_") as tmp:
            path = os.path.join(tmp, name)
            with open(path, "wb") as f:
                f.write(data)
            try:
                result = engine.scan_file(path, password, log=lines.append)
            except Exception as e:
                return self._json(500, {"error": f"스캔 실패: {e}"})
        verdict, _ = engine._verdict(result)
        self._json(200, {
            "verdict": verdict,
            "findings": list(result.findings),
            "carved": len(result.carved),
            "report_html": engine.build_report_html(result),
            "log": "\n".join(lines),
            "seconds": round(time.time() - t0, 1),
        })

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
