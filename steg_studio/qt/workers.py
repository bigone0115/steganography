"""
백그라운드 작업 스레드 (QThread) — UI 프리징 방지.
"""

from PySide6.QtCore import QThread, Signal

from .. import engine, sandbox


class ScanWorker(QThread):
    log = Signal(str)
    finished_ok = Signal(object)   # ScanResult
    failed = Signal(str)

    def __init__(self, path, password="", isolated=True, timeout=180, mem_limit_mb=1024):
        super().__init__()
        self.path = path
        self.password = password
        self.isolated = isolated
        self.timeout = timeout
        self.mem_limit_mb = mem_limit_mb

    def run(self):
        try:
            if self.isolated:
                result = sandbox.run_scan_isolated(
                    self.path, self.password,
                    timeout=self.timeout, mem_limit_mb=self.mem_limit_mb,
                    on_log=self.log.emit)
            else:
                result = engine.scan_file(self.path, self.password, log=self.log.emit)
            self.finished_ok.emit(result)
        except Exception as e:
            self.failed.emit(str(e))


class VtWorker(QThread):
    done = Signal(str, bool)   # message, is_error

    def __init__(self, data, api_key):
        super().__init__()
        self.data = data
        self.api_key = api_key

    def run(self):
        msg, is_err = engine.query_virustotal(self.data, self.api_key)
        self.done.emit(msg, is_err)


class BatchWorker(QThread):
    progress = Signal(int, int, object)   # idx, total, ScanResult
    finished_all = Signal(int)

    def __init__(self, files, password=""):
        super().__init__()
        self.files = files
        self.password = password
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        # 단일 스캔과 동일하게 파일마다 '격리' 자식 프로세스 — 실제 멀웨어를 본체와 분리.
        # 격리 프로세스 여러 개를 동시에 돌리고, 끝나는 순서대로 (원래 번호, 결과)를 보낸다.
        total = len(self.files)
        done = 0
        gen = engine.scan_many(self.files, self.password, isolated=True)
        try:
            for i, result in gen:
                done += 1
                self.progress.emit(i + 1, total, result)
                if self._cancel:
                    break                      # 남은(미시작) 작업은 scan_many가 취소
        finally:
            gen.close()
        self.finished_all.emit(done)
