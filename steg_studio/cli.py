"""
명령줄 인터페이스(CLI) — GUI 없이 터미널/스크립트/서버에서 사용.

GUI와 완전히 분리된 engine/embed 모듈을 호출하므로 Windows·Linux·macOS 어디서든,
디스플레이가 없는 서버에서도 동작한다.

사용 예:
    python -m steg_studio scan  악성.pdf
    python -m steg_studio scan  이미지.png --isolated --json report.json
    python -m steg_studio embed carrier.png payload.py -o out.png --password pw --mode pixelcode
    python -m steg_studio sanitize 의심.png -o 안전본.png
    python -m steg_studio meta 사진.jpg                       (보기)
    python -m steg_studio meta 사진.jpg --scrub               (전체 삭제 사본)
    python -m steg_studio meta 문서.docx --set creator=Anon --set "custom:Dept="   (편집, 빈 값=삭제)

서브커맨드:
    scan      파일 포렌식 스캔 → 리포트 출력/저장
    embed     파일에 데이터 은닉(스테가노그래피)
    sanitize  CDR 무해화(숨겨진 데이터 제거 사본 생성)
"""

import os
import sys
import argparse

from . import engine, embed, sandbox, __version__


# =========================================================================
# scan 서브커맨드
# =========================================================================
def _cmd_scan(args):
    """
    파일을 포렌식 스캔하고 결과를 터미널에 요약 출력한다.
    --isolated: 별도 프로세스(샌드박스)에서 스캔 / --json·--html: 리포트 파일 저장.
    반환: 위협 탐지 시 1, 없으면 0 (스크립트 분기용 종료코드).
    """
    if not os.path.isfile(args.file):
        print(f"[오류] 파일을 찾을 수 없습니다: {args.file}", file=sys.stderr)
        return 2

    # 실시간 로그를 그대로 표준출력에 흘림(조용히 하려면 --quiet)
    log_cb = (lambda line: print(line)) if not args.quiet else None

    try:
        if args.isolated:
            result = sandbox.run_scan_isolated(args.file, args.password, on_log=log_cb)
        else:
            result = engine.scan_file(args.file, args.password, log=log_cb)
    except Exception as e:
        print(f"[오류] 스캔 실패: {e}", file=sys.stderr)
        return 2

    # 요약 출력
    print("\n" + "=" * 60)
    print(f" 파일      : {result.filename} ({result.filesize:,} bytes, {result.carrier_fmt})")
    print(f" SHA-256   : {result.sha256}")
    print(f" 엔트로피  : {result.overall_entropy:.3f} / 8.0")
    print(f" 탐지 항목 : {len(result.carved)}개 / 판정 {len(result.findings)}건")
    for it in result.carved:
        print(f"   - #{it.id} [{it.category}] {it.format} @{it.offset} ({it.size:,} B)")
    print("=" * 60)

    # 리포트 저장
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(engine.build_report_json(result))
        print(f"[+] JSON 리포트 저장: {args.json}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(engine.build_report_html(result))
        print(f"[+] HTML 리포트 저장: {args.html}")

    return 1 if result.findings else 0


# =========================================================================
# embed 서브커맨드
# =========================================================================
def _cmd_embed(args):
    """
    carrier(원본 미디어)에 payload(숨길 파일)를 은닉해 결과 파일을 저장한다.
    --mode: pixelcode(이미지 LSB) / audio_lsb(WAV) / eof_packet(파일끝 결합) / raw_concat(원본 결합).
    반환: 성공 0, 실패 2.
    """
    if not os.path.isfile(args.carrier) or not os.path.isfile(args.payload):
        print("[오류] carrier와 payload 파일이 모두 존재해야 합니다.", file=sys.stderr)
        return 2
    with open(args.payload, "rb") as f:
        payload_bytes = f.read()
    try:
        if args.mode == "pixelcode":
            out, ext, info = embed.embed_pixelcode_lsb(args.carrier, args.payload, payload_bytes, args.password)
        elif args.mode == "audio_lsb":
            out, ext, info = embed.embed_audio_wav_lsb(args.carrier, args.payload, payload_bytes, args.password)
        elif args.mode == "eof_packet":
            out, ext, info = embed.embed_eof_packet(args.carrier, args.payload, payload_bytes, args.password)
        else:  # raw_concat
            out, ext, info = embed.embed_raw_concat(args.carrier, payload_bytes)
    except Exception as e:
        print(f"[오류] 은닉 실패: {e}", file=sys.stderr)
        return 2

    out_path = args.output or (os.path.splitext(args.carrier)[0] + "_stego" + ext)
    with open(out_path, "wb") as f:
        f.write(out)
    print(f"[+] {info}")
    print(f"[+] 저장: {out_path} ({len(out):,} bytes)")
    return 0


# =========================================================================
# sanitize 서브커맨드 (CDR)
# =========================================================================
def _cmd_sanitize(args):
    """
    파일에서 숨겨진 데이터를 제거한 안전 사본(CDR)을 생성한다.
    이미지=하위 2비트 클리어+재인코딩, WAV=LSB 초기화, 그 외=정상 EOF 이후 절단.
    반환: 성공 0, 실패 2.
    """
    if not os.path.isfile(args.file):
        print(f"[오류] 파일을 찾을 수 없습니다: {args.file}", file=sys.stderr)
        return 2
    with open(args.file, "rb") as f:
        file_bytes = f.read()
    _, natural_eof = engine.identify_carrier_and_eof(file_bytes)
    try:
        out, info = engine.cdr_sanitize(file_bytes, args.file, natural_eof)
    except Exception as e:
        print(f"[오류] 무해화 실패: {e}", file=sys.stderr)
        return 2
    out_path = args.output or (os.path.splitext(args.file)[0] + "_cleaned" + os.path.splitext(args.file)[1])
    with open(out_path, "wb") as f:
        f.write(out)
    print(f"[+] {info}")
    print(f"[+] 저장: {out_path} ({len(out):,} bytes)")
    return 0


# =========================================================================
# argparse 구성 및 진입점
# =========================================================================
def _cmd_batch(args):
    """폴더 일괄 스캔 → 요약 출력 + CSV/HTML 리포트. 의심 파일이 있으면 종료코드 1."""
    files = []
    for dp, _, fns in os.walk(args.folder):
        files += [os.path.join(dp, fn) for fn in fns]
        if not args.recursive:
            break
    files = sorted(files)
    workers = args.workers or engine.default_workers()
    print(f"[*] {len(files)}개 파일, 동시 작업 {min(workers, max(1, len(files)))}개")
    results = [None] * len(files)
    # 병렬 스캔 — 끝나는 순서대로 출력, 리포트는 원래 파일 순서로
    for done, (i, r) in enumerate(engine.scan_many(files, args.password, workers=workers), 1):
        results[i] = r
        v, top = engine._verdict(r)
        print(f"[{done}/{len(files)}] {v:2} {r.filename} — {top[:90]}", flush=True)
    if args.csv:
        with open(args.csv, "w", encoding="utf-8", newline="") as f:
            f.write(engine.build_batch_csv(results))
        print(f"[+] CSV 저장: {args.csv}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(engine.build_batch_html(results))
        print(f"[+] HTML 저장: {args.html}")
    return 1 if any(engine._verdict(r)[0] == "의심" for r in results) else 0


def _cmd_diff(args):
    """원본과 의심본 비교."""
    print(engine.diff_files(args.original, args.suspect))
    return 0


def _cmd_meta(args):
    """메타데이터 보기(기본) / --set KEY=VALUE 편집(빈 값=삭제) / --scrub 전체 삭제. 원본은 건드리지 않고 사본 저장."""
    from . import metaedit
    if not os.path.isfile(args.file):
        print(f"[오류] 파일을 찾을 수 없습니다: {args.file}", file=sys.stderr)
        return 2
    with open(args.file, "rb") as f:
        data = f.read()
    try:
        if args.scrub or args.set:
            if args.scrub:
                new, info, suffix = *metaedit.scrub(data), "_scrubbed"
            else:
                changes = dict(kv.split("=", 1) for kv in args.set if "=" in kv)
                new, info, suffix = *metaedit.edit(data, changes), "_edited"
            base, ext = os.path.splitext(args.file)
            out_path = args.output or (base + suffix + ext)
            with open(out_path, "wb") as f:
                f.write(new)
            print(f"[+] {info}")
            print(f"[+] 저장: {out_path} ({len(new):,} bytes)")
            data = new
        fmt, rows, alerts = metaedit.inspect(data)
    except Exception as e:
        print(f"[오류] 메타데이터 처리 실패: {e}", file=sys.stderr)
        return 2
    print(f"포맷: {fmt} · 메타데이터 {len(rows)}개")
    for k, v in rows:
        print(f"  {k}: {v}")
    for a in alerts:
        print(f"  [!] {a}")
    return 0


def build_parser():
    """CLI 인자 파서를 구성해 반환한다 (서브커맨드: scan/embed/sanitize/batch/diff)."""
    p = argparse.ArgumentParser(
        prog="steg_studio",
        description="Stego & Forensic Security Studio — CLI (은닉/탐지/무해화)")
    p.add_argument("--version", action="version", version=f"steg_studio {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="파일 포렌식 스캔")
    sp.add_argument("file", help="검사할 파일")
    sp.add_argument("--password", default="", help="암호화 패킷 복호화 비밀번호")
    sp.add_argument("--isolated", action="store_true", help="별도 프로세스(샌드박스)에서 스캔")
    sp.add_argument("--json", metavar="PATH", help="JSON 리포트 저장 경로")
    sp.add_argument("--html", metavar="PATH", help="HTML 리포트 저장 경로")
    sp.add_argument("--quiet", action="store_true", help="진행 로그 숨김(요약만 출력)")
    sp.set_defaults(func=_cmd_scan)

    ep = sub.add_parser("embed", help="파일에 데이터 은닉")
    ep.add_argument("carrier", help="원본 미디어 파일")
    ep.add_argument("payload", help="숨길 파일")
    ep.add_argument("-o", "--output", help="결과 저장 경로(기본: <carrier>_stego.<ext>)")
    ep.add_argument("--password", default="", help="암호화 비밀번호(비우면 평문 압축)")
    ep.add_argument("--mode", default="pixelcode",
                    choices=["pixelcode", "audio_lsb", "eof_packet", "raw_concat"],
                    help="은닉 기법(기본: pixelcode)")
    ep.set_defaults(func=_cmd_embed)

    zp = sub.add_parser("sanitize", help="CDR 무해화 사본 생성")
    zp.add_argument("file", help="정화할 파일")
    zp.add_argument("-o", "--output", help="결과 저장 경로(기본: <file>_cleaned.<ext>)")
    zp.set_defaults(func=_cmd_sanitize)

    bp = sub.add_parser("batch", help="폴더 일괄 스캔 + CSV/HTML 리포트")
    bp.add_argument("folder", help="검사할 폴더")
    bp.add_argument("-r", "--recursive", action="store_true", help="하위 폴더 포함")
    bp.add_argument("--password", default="", help="암호화 패킷 복호화 비밀번호")
    bp.add_argument("--csv", metavar="PATH", help="CSV 리포트 저장 경로")
    bp.add_argument("--html", metavar="PATH", help="HTML 리포트 저장 경로")
    bp.add_argument("-j", "--workers", type=int, default=0,
                    help=f"동시 스캔 수 (기본: 코어 절반·최대 8 = {engine.default_workers()}, 1=순차)")
    bp.set_defaults(func=_cmd_batch)

    dp = sub.add_parser("diff", help="원본과 의심본 비교(바이트/픽셀 LSB)")
    dp.add_argument("original", help="원본 파일")
    dp.add_argument("suspect", help="의심 파일")
    dp.set_defaults(func=_cmd_diff)

    mp = sub.add_parser("meta", help="메타데이터 보기/편집/삭제(스크럽)")
    mp.add_argument("file", help="대상 파일 (JPEG/PNG/PDF/Office/MP3/MP4)")
    mp.add_argument("--set", action="append", metavar="KEY=VALUE", help="필드 수정(반복 가능, 빈 값=삭제)")
    mp.add_argument("--scrub", action="store_true", help="모든 메타데이터 제거한 사본 저장")
    mp.add_argument("-o", "--output", help="결과 저장 경로(기본: <file>_edited/_scrubbed.<ext>)")
    mp.set_defaults(func=_cmd_meta)

    wp = sub.add_parser("web", help="브라우저용 웹 UI 실행 (도커 등 화면 없는 환경용)")
    wp.add_argument("--host", default="127.0.0.1", help="바인드 주소 (도커 안에서는 0.0.0.0)")
    wp.add_argument("--port", type=int, default=47821, help="포트 (기본 47821)")
    wp.set_defaults(func=_cmd_web)

    return p


def _cmd_web(args):
    """웹 UI 서버 실행(Ctrl+C / docker stop으로 종료)."""
    from . import web
    web.serve(args.host, args.port)
    return 0


def main(argv=None):
    """CLI 진입점. argv 없으면 sys.argv 사용. 서브커맨드 핸들러의 종료코드를 반환."""
    # 한국어 출력이 cp949 등 비UTF-8 콘솔에서 깨지거나 크래시하지 않도록 UTF-8 강제
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
