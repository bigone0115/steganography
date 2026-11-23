"""
Stego & Forensic Security Studio — Qt(PySide6) 실행 진입점.

사용법:
    python run.py

실행이 바로 꺼지면 같은 폴더의 run_error.log 를 확인하세요(크래시 원인 기록).
"""

import os
import sys
import traceback


def main():
    # Windows 작업표시줄이 python.exe 아이콘 대신 우리 아이콘을 쓰도록 고유 AppUserModelID 지정
    # (이 호출이 없으면 setWindowIcon을 해도 작업표시줄엔 파이썬 아이콘이 뜬다). Linux에선 무시.
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("StegStudio.Forensic.Security.1")
        except Exception:
            pass

    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication
    from steg_studio.qt.main_window import MainWindow, APP_ICON
    app = QApplication(sys.argv)
    if os.path.exists(APP_ICON):
        app.setWindowIcon(QIcon(APP_ICON))   # 작업표시줄/독 아이콘
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException:
        # 더블클릭 등으로 콘솔이 바로 닫혀도 원인을 볼 수 있도록 로그 파일로 남기고 콘솔을 붙잡는다.
        tb = traceback.format_exc()
        log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_error.log")
        try:
            with open(log, "w", encoding="utf-8") as f:
                f.write(tb)
        except Exception:
            pass
        sys.stderr.write("\n[실행 실패] 아래 오류로 종료되었습니다.\n\n" + tb + "\n")
        sys.stderr.write(f"(이 내용은 {log} 에도 저장됨)\n")
        try:
            input("\n엔터를 누르면 창이 닫힙니다...")
        except EOFError:
            pass
        sys.exit(1)
