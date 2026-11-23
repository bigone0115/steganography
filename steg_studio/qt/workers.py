"""
백그라운드 작업 스레드 (QThread) — UI 프리징 방지.
"""

import os

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
        total = len(self.files)
        done = 0
        for i, fp in enumerate(self.files, 1):
            if self._cancel:
                break
            # 단일 스캔과 동일하게 자식 프로세스에서 '격리' 실행 — 실제 멀웨어를 본체와 분리.
            try:
                result = sandbox.run_scan_isolated(fp, self.password)
            except Exception as e:
                result = engine.ScanResult(filename=os.path.basename(fp), findings=[f"[격리 스캔 실패] {e}"])
                result.filepath = fp
                try:
                    result.filesize = os.path.getsize(fp)
                except OSError:
                    pass
            done = i
            self.progress.emit(i, total, result)
        self.finished_all.emit(done)
