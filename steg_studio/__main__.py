"""
`python -m steg_studio ...` 실행 시 CLI로 진입하는 모듈.
(GUI 실행은 프로젝트 루트의 run.py 사용)
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
