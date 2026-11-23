"""
프로세스 격리 스캔 실행기.

engine.scan_file을 별도 자식 프로세스(steg_studio.sandbox_runner)에서 실행한다.
- 크래시 격리: 파서 취약점으로 자식이 죽어도 GUI 본체는 안전.
- 자원 상한(크로스플랫폼):
    * Windows → Job Object (메모리 상한 + 프로세스 종료 시 자식 강제 종료)
    * Linux/macOS → preexec setrlimit (RLIMIT_AS 메모리 + RLIMIT_CPU 시간), firejail 있으면 추가 격리
- 시간 상한: timeout 초과 시 강제 종료.
- 네트워크 미사용: 스캔 경로는 네트워크를 쓰지 않음(VT 조회는 부모에서 명시적으로만).

이것은 '크래시·자원고갈 방어' 계층이며, 같은 OS 계정에서 도는 만큼
완전한 보안 경계는 아니다. 확실한 악성 검체는 Windows Sandbox(sandbox.wsb) 사용 권장.
"""

import os
import sys
import pickle
import tempfile
import subprocess

from . import sandbox_runner as R

IS_WINDOWS = (os.name == "nt")


def _project_root():
    # steg_studio/sandbox.py → 상위(패키지) → 상위(프로젝트 루트)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _posix_preexec(mem_limit_mb, cpu_seconds):
    """
    POSIX(리눅스/맥) 자식 프로세스에 자원 상한을 거는 preexec 콜백을 생성한다.
    Windows의 Job Object에 대응하며, 자식이 exec 되기 직전 setrlimit으로:
      - RLIMIT_AS  : 가상 메모리 상한 (메모리 폭탄 방어)
      - RLIMIT_CPU : CPU 시간 상한 (무한 루프/자원고갈 방어)
    를 적용한다. 반환값은 subprocess의 preexec_fn 인자로 넘긴다.
    """
    def _setlimits():
        import resource
        mem_bytes = int(mem_limit_mb) * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        except (ValueError, OSError):
            pass
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (int(cpu_seconds), int(cpu_seconds) + 2))
        except (ValueError, OSError):
            pass
    return _setlimits


def _maybe_firejail(cmd):
    """
    리눅스에 firejail이 설치돼 있으면 명령을 firejail로 감싸 한 단계 더 격리한다.
    (네트워크 차단 + 최소 권한). 없으면 원래 명령을 그대로 반환.
    입력 파일 접근을 위해 파일시스템은 기본 프로파일을 사용한다.
    """
    if IS_WINDOWS:
        return cmd
    import shutil
    fj = shutil.which("firejail")
    if fj:
        return [fj, "--quiet", "--net=none", "--"] + cmd
    return cmd


def _apply_windows_job_limits(pid, mem_limit_mb):
    """자식 프로세스를 Job Object에 넣어 메모리 상한 + kill-on-close 적용. 실패해도 무시."""
    if not IS_WINDOWS:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)

        JobObjectExtendedLimitInformation = 9
        JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        PROCESS_SET_QUOTA = 0x0100
        PROCESS_TERMINATE = 0x0001

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [("ReadOperationCount", ctypes.c_uint64),
                        ("WriteOperationCount", ctypes.c_uint64),
                        ("OtherOperationCount", ctypes.c_uint64),
                        ("ReadTransferCount", ctypes.c_uint64),
                        ("WriteTransferCount", ctypes.c_uint64),
                        ("OtherTransferCount", ctypes.c_uint64)]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        k32.CreateJobObjectW.restype = wintypes.HANDLE
        job = k32.CreateJobObjectW(None, None)
        if not job:
            return None

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        info.ProcessMemoryLimit = int(mem_limit_mb) * 1024 * 1024
        k32.SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                    ctypes.byref(info), ctypes.sizeof(info))

        k32.OpenProcess.restype = wintypes.HANDLE
        hproc = k32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, int(pid))
        if hproc:
            k32.AssignProcessToJobObject(job, hproc)
            k32.CloseHandle(hproc)
        # job 핸들은 반환해 부모가 들고 있어야 kill-on-close가 유지됨
        return job
    except Exception:
        return None


def run_scan_isolated(path, password="", timeout=180, mem_limit_mb=1024, on_log=None):
    """
    자식 프로세스에서 스캔을 실행하고 ScanResult를 반환한다.
    on_log: 실시간 로그 콜백(str). timeout 초과·크래시·메모리 초과 시 예외 발생.
    """
    fd, outfile = tempfile.mkstemp(suffix=".pkl", prefix="steg_scan_")
    os.close(fd)
    env = dict(os.environ)
    env["STEG_SCAN_PW"] = password
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = _project_root() + os.pathsep + env.get("PYTHONPATH", "")

    creationflags = 0
    if IS_WINDOWS:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    cmd = _maybe_firejail([sys.executable, "-m", "steg_studio.sandbox_runner", path, outfile])

    # 플랫폼별 자원 격리: Windows=Job Object(아래), POSIX=preexec setrlimit(여기)
    preexec = None if IS_WINDOWS else _posix_preexec(mem_limit_mb, timeout)

    proc = subprocess.Popen(
        cmd, cwd=_project_root(), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
        creationflags=creationflags,
        preexec_fn=preexec,
    )
    job = _apply_windows_job_limits(proc.pid, mem_limit_mb)

    err_detail = None
    try:
        import threading
        done = {"ok": False}

        def reader():
            for line in proc.stdout:
                line = line.rstrip("\n")
                if line.startswith(R.LOG_PREFIX):
                    if on_log:
                        on_log(line[len(R.LOG_PREFIX):].replace("\\n", "\n"))
                elif line.startswith(R.DONE_MARK):
                    done["ok"] = True
                elif line.startswith(R.ERR_PREFIX):
                    done["err"] = line[len(R.ERR_PREFIX):]

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise TimeoutError(f"스캔이 제한 시간({timeout}s)을 초과하여 중단되었습니다 (격리 프로세스 강제 종료).")
        t.join(timeout=5)

        err_detail = done.get("err")
        if proc.returncode != 0 or not done.get("ok"):
            if err_detail:
                raise RuntimeError(f"격리 스캔 실패: {err_detail}")
            raise RuntimeError(
                f"격리 스캔 프로세스가 비정상 종료되었습니다 (exit={proc.returncode}). "
                "대상 파일이 파서를 크래시시켰거나 메모리 상한을 초과했을 수 있습니다.")

        with open(outfile, "rb") as f:
            return pickle.load(f)
    finally:
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass
        if job and IS_WINDOWS:
            try:
                import ctypes
                ctypes.WinDLL("kernel32").CloseHandle(job)
            except Exception:
                pass
        try:
            os.remove(outfile)
        except OSError:
            pass
