"""End-to-end integration test for the login service.

Spins up TWO uvicorn processes sharing one SQLite file (same topology as the
docker-compose deployment) and verifies:

  1. basic login / session cookie / identity / logout
  2. per-account slot accounting across both processes
  3. atomic reservation: a 6th concurrent attempt gets an immediate 429
     (fast => no argon2 hashing, Retry-After header present)
  4. errors counted at completion time; correct password blocked at capacity
  5. rolling window expiry restores slots
  6. client disconnect does NOT release slots: verification still settles
  7. success clears completed errors; later in-flight failures still count
  8. restart keeps windowed errors and reclaims stale in-flight slots
  9. only password hashes are stored (no plaintext in the database)
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
# Unique per invocation: restricted sandboxes may forbid killing orphaned
# servers from an earlier crashed run, so never reuse ports/db paths.
_RUN_ID = os.environ.get("IT_RUN_ID", str(int(time.time() * 1000)))
DB_DIR = Path(f"/tmp/login-guard-it-{_RUN_ID}")
DB_PATH = DB_DIR / "login.db"
PORTS = {"web1": 8201 + (int(_RUN_ID) % 100),
         "web2": 8301 + (int(_RUN_ID) % 100)}
WINDOW = 5
MAX_SLOTS = 5
BASE = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}

failures: list[str] = []


def check(cond: bool, label: str) -> None:
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {label}")
    if not cond:
        failures.append(label)


def reset_db() -> None:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        conn.execute("DELETE FROM login_inflight")
        conn.execute("DELETE FROM login_errors")
        conn.execute("DELETE FROM sessions")
        conn.commit()
    finally:
        conn.close()


def stats(base: str) -> dict:
    r = httpx.get(f"{base}/api/stats", timeout=10)
    r.raise_for_status()
    return r.json()


def account_stat(base: str, username: str) -> dict:
    return next(a for a in stats(base)["accounts"] if a["username"] == username)


def wait_ready(base: str, timeout: float = 25.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{base}/api/stats", timeout=2).status_code == 200:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"service at {base} never became ready")


def start_process(name: str) -> subprocess.Popen:
    env = os.environ.copy()
    env.update(
        {
            "LOGIN_DB_PATH": str(DB_PATH),
            "PROCESS_NAME": name,
            "ERROR_WINDOW_SECONDS": str(WINDOW),
            "MAX_SLOTS": str(MAX_SLOTS),
            "MAX_DELAY_SECONDS": "10",
            "PYTHONPATH": str(ROOT),
        }
    )
    log = open(DB_DIR / f"{name}.log", "w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(PORTS[name]), "--no-access-log"],
        cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    wait_ready(BASE[name])
    return proc


def login(base: str, username: str, password: str, delay: float = 0.0,
          timeout: float = 30.0):
    return httpx.post(
        f"{base}/api/login",
        json={"username": username, "password": password, "delay": delay},
        timeout=timeout,
    )


def stop_process(proc: subprocess.Popen) -> bool:
    """Best-effort SIGTERM. Returns False when the sandbox forbids signals."""
    if proc.poll() is not None:
        return True
    try:
        proc.terminate()  # SIGTERM on POSIX
        proc.wait(timeout=15)
        return True
    except (PermissionError, ProcessLookupError):
        return False
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=5)
            return True
        except PermissionError:
            return False


def run_startup_cleanup() -> None:
    """Execute exactly the startup hook (db.init_db) in a fresh process.

    On a real Docker restart the new container process runs this same code
    against the same volume; all slot state lives in SQLite, so a separate
    short-lived process is a faithful equivalent when the sandbox forbids
    killing the long-running servers.
    """
    env = os.environ.copy()
    env.update(
        {
            "LOGIN_DB_PATH": str(DB_PATH),
            "ERROR_WINDOW_SECONDS": str(WINDOW),
            "MAX_SLOTS": str(MAX_SLOTS),
            "PYTHONPATH": str(ROOT),
        }
    )
    subprocess.run(
        [sys.executable, "-c", "from app.db import init_db; init_db()"],
        cwd=str(ROOT), env=env, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def main() -> int:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    for p in DB_DIR.glob("login.db*"):
        p.unlink()

    procs = {name: start_process(name) for name in PORTS}
    try:
        # ---- 1. basics ----------------------------------------------------
        print("1. 基本登录 / 会话 / 身份 / 退出")
        r = login(BASE["web1"], "alice", "wrong")
        check(r.status_code == 401, "错误密码返回 401")
        r = login(BASE["web2"], "alice", "alice-pass-2026")
        check(r.status_code == 200, "正确密码返回 200")
        cookie = r.headers.get("set-cookie", "")
        check("httponly" in cookie.lower(), "会话 Cookie 带 HttpOnly")
        check(r.json()["served_by"] == "web2", "响应由 web2 进程处理")
        client = httpx.Client(base_url=BASE["web1"], cookies=r.cookies)
        me = client.get("/api/me")
        check(me.status_code == 200 and me.json()["username"] == "alice",
              "跨进程携带 HttpOnly 会话可查看当前身份")
        check(client.post("/api/logout").status_code == 204, "退出登录 204")
        check(client.get("/api/me").status_code == 401, "退出后身份查询 401")

        # ---- 2. cross-process shared view --------------------------------
        print("2. 两进程共享同一名额视图")
        reset_db()
        s1 = account_stat(BASE["web1"], "bob")
        s2 = account_stat(BASE["web2"], "bob")
        check(s1 == s2 and s1["remaining_slots"] == MAX_SLOTS,
              "两进程看到一致的初始名额")
        r = login(BASE["web1"], "bob", "nope")
        check(r.status_code == 401 and r.headers["X-Served-By"] == "web1",
              "web1 记录一次错误")
        check(account_stat(BASE["web2"], "bob")["window_errors"] == 1,
              "web2 立刻看到 web1 写入的错误")

        # ---- 3. atomic reservation + immediate 429, no hashing -----------
        print("3. 原子占位：满额立即 429 且不做哈希")
        reset_db()
        barrier = threading.Barrier(6)

        def attempt(i):
            barrier.wait()
            return login(BASE["web1" if i % 2 else "web2"],
                         "alice", "wrong", delay=2.0, timeout=30)

        with ThreadPoolExecutor(max_workers=6) as pool:
            futs = [pool.submit(attempt, i) for i in range(6)]
            results = [f.result() for f in futs]
        statuses = sorted(r.status_code for r in results)
        check(statuses == [401, 401, 401, 401, 401, 429],
              f"5 个进入核验、第 6 个 429（实际状态码 {statuses}）")
        limited = next(r for r in results if r.status_code == 429)
        check("retry-after" in {k.lower() for k in limited.headers.keys()},
              "429 带 Retry-After 头")
        check(limited.elapsed.total_seconds() < 1.5,
              f"429 立即返回（{limited.elapsed.total_seconds():.2f}s < 1.5s，未做 argon2/未睡延迟）")
        st = account_stat(BASE["web1"], "alice")
        check(st["window_errors"] == 5 and st["inflight"] == 0
              and st["remaining_slots"] == 0,
              "结算后错误=5、在途=0、剩余=0")

        # ---- 4. capacity blocks even the correct password ---------------
        print("4. 满额时正确密码同样立即 429")
        t0 = time.time()
        r = login(BASE["web2"], "alice", "alice-pass-2026")
        check(r.status_code == 429 and time.time() - t0 < 1.0,
              "满额后正确密码也被快速 429")

        # ---- 5. window expiry --------------------------------------------
        print(f"5. 滑动窗口（{WINDOW}s）过期后名额恢复")
        deadline = time.time() + WINDOW + 8
        while time.time() < deadline:
            if account_stat(BASE["web1"], "alice")["remaining_slots"] == MAX_SLOTS:
                break
            time.sleep(0.3)
        check(account_stat(BASE["web1"], "alice")["remaining_slots"] == MAX_SLOTS,
              "窗口滑过后名额恢复为 5")
        r = login(BASE["web1"], "alice", "alice-pass-2026")
        check(r.status_code == 200, "恢复后正确密码可登录")

        # ---- 6. disconnect does not release the slot ---------------------
        print("6. 客户端断连后核验仍完成并结算（不提前归还名额）")
        reset_db()
        def disconnecting_attempt(i):
            try:
                login(BASE["web1"], "bob", "wrong", delay=2.0, timeout=0.5)
            except httpx.TimeoutException:
                return "aborted"
            return "unexpected"

        with ThreadPoolExecutor(max_workers=3) as pool:
            futs = [pool.submit(disconnecting_attempt, i) for i in range(3)]
            time.sleep(0.9)  # requests already in-flight server-side
            mid = account_stat(BASE["web2"], "bob")
            check(mid["inflight"] == 3 and mid["window_errors"] == 0,
                  "客户端已超时断开，服务端在途仍为 3")
            outcomes = [f.result() for f in futs]
            check(outcomes == ["aborted"] * 3, "三个客户端均已断开")
        deadline = time.time() + 6
        while time.time() < deadline:
            st = account_stat(BASE["web1"], "bob")
            if st["inflight"] == 0:
                break
            time.sleep(0.2)
        st = account_stat(BASE["web1"], "bob")
        check(st["inflight"] == 0 and st["window_errors"] == 3,
              "断连的请求在服务端完成核验并计入 3 个错误")

        # ---- 7. success clears completed errors, late failures still count
        print("7. 成功清除已完成错误；其他在途请求随后出错仍计数")
        reset_db()
        for _ in range(2):
            check(login(BASE["web1"], "alice", "wrong").status_code == 401,
                  "预置 2 个已完成错误")
        check(account_stat(BASE["web1"], "alice")["window_errors"] == 2,
              "当前错误=2")

        start_event = threading.Event()

        def slow_wrong():
            start_event.wait()
            return login(BASE["web2"], "alice", "wrong", delay=2.5, timeout=30)

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(slow_wrong)
            f2 = pool.submit(slow_wrong)
            start_event.set()  # both requests start together
            time.sleep(0.8)  # ensure both slots are acquired before continuing
            ok = login(BASE["web1"], "alice", "alice-pass-2026")
            check(ok.status_code == 200, "在途期间正确密码登录成功")
            st = account_stat(BASE["web1"], "alice")
            check(st["window_errors"] == 0 and st["inflight"] == 2,
                  "成功清除当时已完成错误，2 个在途不受影响")
            rs = [f1.result().status_code, f2.result().status_code]
            check(sorted(rs) == [401, 401], "两个慢请求随后失败")
        st = account_stat(BASE["web2"], "alice")
        check(st["window_errors"] == 2 and st["inflight"] == 0,
              "后完成的在途错误仍然计数（错误=2）")

        # ---- 8. restart persistence --------------------------------------
        print("8. 重启保留窗口内错误、清理未完成占位")
        reset_db()
        check(login(BASE["web1"], "bob", "wrong").status_code == 401,
              "制造 1 个已完成错误")
        pool = ThreadPoolExecutor(max_workers=2)
        futs = [
            pool.submit(lambda: login(BASE["web1"], "bob", "wrong",
                                      delay=4.0, timeout=30)),
            pool.submit(lambda: login(BASE["web2"], "bob", "wrong",
                                      delay=4.0, timeout=30)),
        ]
        time.sleep(1.0)
        check(account_stat(BASE["web1"], "bob")["inflight"] == 2,
              "重启前存在 2 个在途占位")

        stopped = all(stop_process(p) for p in procs.values())
        if stopped:
            # Real restart path: servers died with requests in flight.
            check(not any(f.done() for f in futs),
                  "客户端请求随进程关闭而未完成")
            procs = {name: start_process(name) for name in PORTS}
        else:
            # Sandbox blocks signals: simulate the restart by running the
            # exact startup hook in a fresh process against the same DB.
            run_startup_cleanup()
        st = account_stat(BASE["web1"], "bob")
        check(st["inflight"] == 0, "重启后未完成占位已清空")
        check(st["window_errors"] == 1, "窗口内错误在重启后保留")
        late_codes = []
        for f in futs:
            try:
                late_codes.append(f.result(timeout=10).status_code)
            except Exception:
                late_codes.append("transport")
        pool.shutdown(wait=True)
        if not stopped:
            # The verifiers finished after their slots were reclaimed: they
            # must settle gracefully (401, not a 500) and must not resurrect
            # slots or double-count errors.
            check(all(c in (401, "transport") for c in late_codes),
                  f"占位被回收后的延迟核验不产生 500（实际 {late_codes}）")
        st = account_stat(BASE["web2"], "bob")
        check(st["inflight"] == 0 and st["window_errors"] == 1,
              "延迟核验结束后无残留占位、错误不重复计数")
        reset_db()  # keep state clean for subsequent assertions

        # ---- 9. no plaintext passwords at rest ---------------------------
        print("9. 数据库仅存哈希")
        conn = sqlite3.connect(DB_PATH)
        try:
            rows = conn.execute(
                "SELECT username, password_hash FROM accounts ORDER BY username"
            ).fetchall()
            check([u for u, _ in rows] == ["alice", "bob"], "预置两个账号")
            all_argon = all(h.startswith("$argon2id$") for _, h in rows)
            check(all_argon, "密码字段均为 argon2id 哈希")
            dumped = "\n".join(
                str(r) for r in conn.execute(
                    "SELECT name, sql FROM sqlite_master").fetchall())
            for plain in ("alice-pass-2026", "bob-pass-2026"):
                check(plain not in dumped, f"库结构中无明文 {plain}")
        finally:
            conn.close()

        # ---- 10. server logs contain no unhandled exceptions -------------
        print("10. 服务端日志无未处理异常")
        for name in PORTS:
            log_text = (DB_DIR / f"{name}.log").read_text(errors="replace")
            check("Traceback" not in log_text and "RuntimeError" not in log_text,
                  f"{name} 日志无 Traceback/RuntimeError")

    finally:
        for proc in procs.values():
            stop_process(proc)

    print()
    if failures:
        print(f"{len(failures)} 项失败：")
        for f in failures:
            print(" -", f)
        return 1
    print("全部检查通过 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
