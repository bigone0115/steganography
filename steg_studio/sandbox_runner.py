"""
격리 스캔 자식 프로세스 진입점.

별도 프로세스에서 engine.scan_file을 실행하여, 악의적으로 조작된 입력이
파서(Pillow/zlib/wave 등) 취약점을 건드려 크래시·폭주하더라도 GUI 본체와
격리되도록 한다. 로그는 stdout으로 스트리밍하고, 최종 ScanResult는 pickle로 저장.

사용(부모가 호출):
    python -m steg_studio.sandbox_runner <input_file> <output_pickle>
    비밀번호는 환경변수 STEG_SCAN_PW 로 전달(명령줄 노출 방지).
"""

import os
import sys
import pickle

LOG_PREFIX = "\x01LOG\x01"
DONE_MARK = "\x01DONE\x01"
ERR_PREFIX = "\x01ERR\x01"


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: sandbox_runner <input_file> <output_pickle>\n")
        return 2
    infile, outfile = sys.argv[1], sys.argv[2]
    password = os.environ.get("STEG_SCAN_PW", "")

    def log(line):
        sys.stdout.write(LOG_PREFIX + line.replace("\n", "\\n") + "\n")
        sys.stdout.flush()

    from steg_studio import engine
    try:
        result = engine.scan_file(infile, password, log=log)
        with open(outfile, "wb") as f:
            pickle.dump(result, f, protocol=pickle.HIGHEST_PROTOCOL)
        sys.stdout.write(DONE_MARK + "\n")
        sys.stdout.flush()
        return 0
    except Exception as e:
        sys.stdout.write(ERR_PREFIX + f"{type(e).__name__}: {e}\n")
        sys.stdout.flush()
        return 1


if __name__ == "__main__":
    sys.exit(main())
