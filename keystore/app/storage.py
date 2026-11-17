"""密钥服务持久化层（SQLite，挂载在独立持久卷上）。

表：
  master_keys  主密钥本体（随机 32 字节）、state(active/destroyed)、
               生命周期 lifecycle(active/purge_pending/purged)、清退阶段与
               错误、时间戳
  meta         单例行：当前生效主密钥 id
  idem_log     幂等令牌 -> 首次响应，保证 rotate/rewrap 重放得到同一结果

主密钥只存在本服务进程内存与本卷的 SQLite 中。

销毁语义（两段式，避免"只把当前行零覆写"却把旧密钥留在 WAL/空闲页）：
  1. destroy_master() 先把密钥材料置零、state='destroyed'，并持久化
     lifecycle='purge_pending' + purge_phase='zero_material'。此时密钥已
     不可解包（unwrap/rewrap 一律 410）。
  2. 后台常驻线程按持久化阶段逐步清退本卷中的旧密钥材料：
        zero_material -> single_file -> compacted -> shredded -> restored
     * zero_material  再次确认 key_material = 32 个零字节；
     * single_file    WAL checkpoint(TRUNCATE) 并切到 DELETE 日志模式，
                      使旧 WAL 中残留的历史页落盘后被移除；
     * compacted      用 VACUUM 重建整个数据库文件：所有空闲页被丢弃，
                      旧密钥材料不再留在空闲页/历史页中；
     * shredded       关闭连接后对本库的 WAL/SHM/journal 等旁路文件做多次
                      覆写、截断、删除并 fsync 目录（主库此时已被 VACUUM 重建，
                      不含旧材料，绝不能被销毁）；
     * restored       重新打开为 WAL，checkpoint、integrity_check、复核密钥列为
                      零，最后置 lifecycle='purged'。
  阶段全部持久化在 master_keys 行里：清理受阻或进程中断后，重启时后台线程
  从记录下来的阶段继续，幂等重放每一步。
  只有 lifecycle='purged' 才算销毁完成；destroy 接口在返回前等待清退核实，
  受阻则返回 503（可重试），绝不提前报告销毁完成。
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from typing import Optional

from .crypto_envelope import new_data_key, unwrap_dek, wrap_dek

SCHEMA = """
CREATE TABLE IF NOT EXISTS master_keys (
    key_id       TEXT PRIMARY KEY,
    key_material BLOB NOT NULL,
    state        TEXT NOT NULL CHECK (state IN ('active','destroyed')),
    created_at   REAL NOT NULL,
    destroyed_at REAL,
    lifecycle    TEXT NOT NULL DEFAULT 'active',
    purge_phase  TEXT,
    purge_error  TEXT,
    purge_attempts INTEGER NOT NULL DEFAULT 0,
    material_zeroed_at REAL,
    purge_verified_at  REAL
);
CREATE TABLE IF NOT EXISTS meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    current_key_id TEXT
);
INSERT OR IGNORE INTO meta (id, current_key_id) VALUES (1, NULL);
CREATE TABLE IF NOT EXISTS idem_log (
    token        TEXT PRIMARY KEY,
    status_code  INTEGER NOT NULL,
    response     TEXT NOT NULL,
    created_at   REAL NOT NULL
);
"""

# 清退阶段（持久化在 master_keys.purge_phase，可从中断处接续）
PHASE_ZERO = "zero_material"
PHASE_SINGLE = "single_file"
PHASE_COMPACT = "compacted"
PHASE_SHRED = "shredded"
PHASE_RESTORE = "restored"
PHASE_DONE = "done"

SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal", "-mj")


class KeyError_(Exception):
    """业务错误：携带 HTTP 状态码与错误码。"""

    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class PurgeBlocked(Exception):
    """清退暂时受阻（锁、journal 模式切换失败等），保留阶段稍后重试。"""


class PurgeInterrupted(Exception):
    """服务关闭导致清退中断，保留阶段等下次启动继续。"""


def _fsync_dir(dirpath: str) -> None:
    try:
        fd = os.open(dirpath, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _shred_file(path: str, passes: int) -> int:
    """覆写 -> fsync -> 截断 -> 删除 -> fsync 目录。返回原文件大小。

    先覆写内容再 unlink，确保本卷上的旁路文件（旧 WAL/日志）不再含旧密钥
    字节；文件不存在视为已清理（幂等）。
    """
    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        return 0
    if size:
        chunk = 64 * 1024
        with open(path, "r+b", buffering=0) as fh:
            for i in range(max(1, passes)):
                if i == 0:
                    pattern = os.urandom(chunk)
                elif i == 1:
                    pattern = b"\x00" * chunk
                else:
                    pattern = b"\xff" * chunk
                fh.seek(0)
                remaining = size
                while remaining > 0:
                    n = min(chunk, remaining)
                    fh.write(pattern[:n])
                    remaining -= n
                os.fsync(fh.fileno())
            fh.truncate(0)
            os.fsync(fh.fileno())
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    _fsync_dir(os.path.dirname(os.path.abspath(path)))
    return size


class KeyStore:
    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._db_path = os.path.abspath(db_path)
        self._db_dir = os.path.dirname(self._db_path)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._closed = False
        self._backoff: dict[str, float] = {}
        self._purge_wait = float(os.environ.get("KEY_PURGE_WAIT_SECONDS", "10"))
        self._scrub_passes = int(os.environ.get("KEY_PURGE_SCRUB_PASSES", "3"))
        # 故障注入：命名的阶段总是失败（演练清理受阻 + 重启接续）
        self._block_phase = os.environ.get("KEY_PURGE_BLOCK_PHASE", "").strip()
        self._conn = self._new_conn()
        with self._lock:
            self._init_schema()
        self._purge_thread = threading.Thread(
            target=self._purge_loop, daemon=True, name="keystore-purge")
        self._purge_thread.start()

    # ---- 连接 / schema --------------------------------------------------
    def _new_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30, check_same_thread=False,
                               isolation_level=None)  # 显式事务，便于 VACUUM
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        # 主密钥状态变更必须落盘后才算数
        conn.execute("PRAGMA synchronous=FULL")
        # 删除行时把内容覆写为零，减少空闲页/历史页中的旧密钥残留
        conn.execute("PRAGMA secure_delete=ON")
        # VACUUM 等排序临时数据只放内存，绝不写含历史页的临时文件
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _init_schema(self) -> None:
        self._conn.executescript(SCHEMA)
        cols = {r["name"] for r in self._conn.execute(
            "PRAGMA table_info(master_keys)")}
        additions = {
            "lifecycle": "TEXT NOT NULL DEFAULT 'active'",
            "purge_phase": "TEXT",
            "purge_error": "TEXT",
            "purge_attempts": "INTEGER NOT NULL DEFAULT 0",
            "material_zeroed_at": "REAL",
            "purge_verified_at": "REAL",
        }
        for name, ddl in additions.items():
            if name not in cols:
                self._conn.execute(
                    f"ALTER TABLE master_keys ADD COLUMN {name} {ddl}")
        # 旧版本只做了行内零覆写就报 destroyed：其卷内 WAL/空闲页可能仍有
        # 旧密钥材料，升级后一律重新排队清退（阶段从 zero_material 起，幂等）。
        self._conn.execute(
            "UPDATE master_keys SET lifecycle='purge_pending', "
            "purge_phase=CASE WHEN purge_phase IS NULL OR purge_phase='' "
            "THEN 'zero_material' ELSE purge_phase END "
            "WHERE state='destroyed' AND lifecycle <> 'purged'")

    # ---- 内部工具 -------------------------------------------------------
    def _get_key_row(self, cur, key_id: str) -> sqlite3.Row:
        row = cur.execute(
            "SELECT * FROM master_keys WHERE key_id = ?", (key_id,)
        ).fetchone()
        if row is None:
            raise KeyError_(404, "key_not_found", f"master key {key_id} not found")
        return row

    def current_key_id(self) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT current_key_id FROM meta WHERE id = 1"
            ).fetchone()
            return row["current_key_id"]

    # ---- 主密钥生命周期 -------------------------------------------------
    def ensure_bootstrap(self) -> dict:
        """无主密钥时自动生成第一把（API 服务首次启动会调用）。"""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = cur.execute(
                    "SELECT current_key_id FROM meta WHERE id = 1"
                ).fetchone()
                if row["current_key_id"]:
                    key_id = row["current_key_id"]
                    created = cur.execute(
                        "SELECT created_at FROM master_keys WHERE key_id=?", (key_id,)
                    ).fetchone()
                    cur.execute("COMMIT")
                    return {"key_id": key_id, "created_at": created["created_at"],
                            "bootstrapped": False}
                key_id = "mk-" + uuid.uuid4().hex
                now = time.time()
                cur.execute(
                    "INSERT INTO master_keys (key_id, key_material, state, "
                    "lifecycle, created_at) VALUES (?,?, 'active', 'active', ?)",
                    (key_id, os.urandom(32), now),
                )
                cur.execute("UPDATE meta SET current_key_id=? WHERE id=1", (key_id,))
                cur.execute("COMMIT")
                return {"key_id": key_id, "created_at": now, "bootstrapped": True}
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def rotate_master(self, token: Optional[str] = None) -> dict:
        """生成新主密钥并切为当前；旧主密钥保留 active 待迁移完成后销毁。
        幂等：同一 token 的重试返回同一次轮换结果，不重复生成 MK。"""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                if token:
                    cached = cur.execute(
                        "SELECT response FROM idem_log WHERE token=?", (token,)
                    ).fetchone()
                    if cached is not None:
                        cur.execute("COMMIT")
                        import json
                        return {**json.loads(cached["response"]),
                                "idempotent": True}
                old_id = cur.execute(
                    "SELECT current_key_id FROM meta WHERE id=1"
                ).fetchone()["current_key_id"]
                new_id = "mk-" + uuid.uuid4().hex
                now = time.time()
                cur.execute(
                    "INSERT INTO master_keys (key_id, key_material, state, "
                    "lifecycle, created_at) VALUES (?,?, 'active', 'active', ?)",
                    (new_id, os.urandom(32), now),
                )
                cur.execute("UPDATE meta SET current_key_id=? WHERE id=1", (new_id,))
                result = {"new_key_id": new_id, "old_key_id": old_id}
                if token:
                    import json
                    cur.execute(
                        "INSERT OR IGNORE INTO idem_log "
                        "(token, status_code, response, created_at) VALUES (?,?,?,?)",
                        (token, 200, json.dumps(result), now),
                    )
                cur.execute("COMMIT")
                return result
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def destroy_master(self, key_id: str) -> dict:
        """销毁主密钥并把本卷旧材料清退到可核实为零残留后才返回。

        重复销毁幂等：已 purged 的密钥直接返回 idempotent；已 destroyed 但
        尚未 purged 的会继续（或重新）驱动清退，仍等到核实后才返回。
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = self._get_key_row(cur, key_id)
                now = time.time()
                if row["state"] == "destroyed":
                    already = True
                    destroyed_at = row["destroyed_at"]
                    if row["lifecycle"] != "purged":
                        cur.execute(
                            "UPDATE master_keys SET lifecycle='purge_pending', "
                            "purge_phase=CASE WHEN purge_phase IS NULL OR "
                            "purge_phase='' THEN ? ELSE purge_phase END, "
                            "purge_error=NULL WHERE key_id=? AND "
                            "lifecycle <> 'purged'",
                            (PHASE_ZERO, key_id))
                else:
                    already = False
                    destroyed_at = now
                    cur.execute(
                        "UPDATE master_keys SET key_material=zeroblob(32), "
                        "state='destroyed', destroyed_at=?, "
                        "lifecycle='purge_pending', purge_phase=?, "
                        "material_zeroed_at=?, purge_error=NULL, "
                        "purge_attempts=0 WHERE key_id=?",
                        (now, PHASE_ZERO, now, key_id))
                    # 若销毁的恰为当前密钥（仅测试/异常路径），清空 current 指针
                    cur.execute(
                        "UPDATE meta SET current_key_id=NULL "
                        "WHERE id=1 AND current_key_id=?",
                        (key_id,))
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise
        # 驱动后台清退并等待核实；受阻/中断 -> 503，阶段保留可接续
        self._backoff.pop(key_id, None)
        self._wake.set()
        purge = self._await_purge(key_id)
        return {"key_id": key_id, "state": "destroyed",
                "destroyed_at": destroyed_at, "idempotent": already,
                "lifecycle": "purged", "material_purged": True,
                "purged_at": purge["purged_at"],
                "purge_phase": purge["purge_phase"],
                "scrub_passes": self._scrub_passes}

    def status(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT key_id, state, lifecycle, purge_phase, purge_error, "
                "purge_attempts, created_at, destroyed_at, purge_verified_at "
                "FROM master_keys ORDER BY created_at"
            ).fetchall()
            keys = []
            for row in rows:
                entry = dict(row)
                # 明确区分"已不可解包"与"销毁完成（材料已清退核实）"：
                # 只有后者才是销毁完成，客户端不必自行推断 lifecycle。
                entry["destroy_complete"] = entry["lifecycle"] == "purged"
                keys.append(entry)
            return {
                "current_key_id": self.current_key_id(),
                "keys": keys,
            }

    def purge_pending(self) -> dict:
        """未完成清退的密钥与当前阶段（只读，供运维/API 核实）。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT key_id, state, lifecycle, purge_phase, purge_error, "
                "purge_attempts, destroyed_at FROM master_keys "
                "WHERE lifecycle='purge_pending' ORDER BY destroyed_at"
            ).fetchall()
            return {"pending": [dict(r) for r in rows]}

    # ---- 清退（后台线程 + 可接续阶段） ---------------------------------
    def _await_purge(self, key_id: str) -> dict:
        deadline = time.time() + self._purge_wait
        while True:
            with self._lock:
                row = self._conn.execute(
                    "SELECT lifecycle, purge_phase, purge_error, "
                    "purge_verified_at FROM master_keys WHERE key_id=?",
                    (key_id,)).fetchone()
            if row is None:
                raise KeyError_(404, "key_not_found",
                                f"master key {key_id} not found")
            if row["lifecycle"] == "purged":
                return {"purged_at": row["purge_verified_at"],
                        "purge_phase": row["purge_phase"]}
            if time.time() >= deadline:
                detail = row["purge_error"] or "purge in progress"
                raise KeyError_(
                    503, "key_purge_blocked",
                    f"master key {key_id} destroyed but key material purge is "
                    f"not verified (phase={row['purge_phase']}): {detail}. "
                    f"Purge will resume; destruction is not reported complete.")
            time.sleep(0.05)

    def _purge_loop(self) -> None:
        while not self._stop.is_set():
            try:
                key_id = self._next_pending()
            except Exception:  # 连接短暂不可用：尝试恢复后等下一轮
                self._reconnect()
                key_id = None
            if key_id is None:
                self._wake.wait(1.0)
                self._wake.clear()
                continue
            self._wake.clear()
            try:
                self._purge_one(key_id)
            except PurgeInterrupted:
                return
            except PurgeBlocked as exc:
                self._record_purge_error(key_id, str(exc))
                # 只让当前这把密钥退避：其他待清退密钥仍可继续推进，
                # 避免持续受阻的密钥饿死别的密钥清退。
                self._backoff[key_id] = time.time() + 0.5
                self._stop.wait(0.1)
            except Exception as exc:  # noqa: BLE001 - 保留阶段，稍后重试
                self._record_purge_error(key_id, repr(exc))
                self._backoff[key_id] = time.time() + 2.0
                self._reconnect()
                self._stop.wait(0.2)

    def _next_pending(self) -> Optional[str]:
        """取下一把待清退密钥；仍在退避期内且还有其他候选时跳过它。"""
        now = time.time()
        with self._lock:
            if self._closed:
                return None
            rows = self._conn.execute(
                "SELECT key_id FROM master_keys WHERE lifecycle='purge_pending' "
                "ORDER BY destroyed_at, key_id").fetchall()
        if not rows:
            return None
        ids = [r["key_id"] for r in rows]
        ready = [k for k in ids if self._backoff.get(k, 0) <= now]
        if ready:
            return ready[0]
        # 全部在退避：取最早到期的那把，必要时短暂休眠
        earliest = min(self._backoff.get(k, 0) for k in ids)
        self._stop.wait(min(max(earliest - now, 0.05), 1.0))
        return ids[0]

    def _reconnect(self) -> None:
        """连接在清退过程中被关闭/损坏时重建，保证阶段能继续推进。"""
        with self._lock:
            if self._closed or self._stop.is_set():
                return
            try:
                self._conn.execute("SELECT 1")
                return
            except Exception:
                pass
            try:
                self._conn.close()
            except Exception:
                pass
            try:
                self._conn = self._new_conn()
                self._init_schema()
            except Exception:
                pass

    def _purge_one(self, key_id: str) -> None:
        handlers = {
            PHASE_ZERO: self._phase_zero_material,
            PHASE_SINGLE: self._phase_single_file,
            PHASE_COMPACT: self._phase_compacted,
            PHASE_SHRED: self._phase_shredded,
            PHASE_RESTORE: self._phase_restored,
        }
        while not self._stop.is_set():
            with self._lock:
                row = self._conn.execute(
                    "SELECT lifecycle, purge_phase FROM master_keys "
                    "WHERE key_id=?", (key_id,)).fetchone()
            if row is None or row["lifecycle"] != "purge_pending":
                return
            phase = row["purge_phase"] or PHASE_ZERO
            if phase == PHASE_DONE:
                # 旧数据/异常窗口：阶段已 done 但 lifecycle 未落 purged。
                # 不直接信任，退回 restored 阶段重新核验后才算完成。
                phase = PHASE_RESTORE
                with self._lock:
                    self._conn.execute(
                        "UPDATE master_keys SET purge_phase=? WHERE key_id=? "
                        "AND lifecycle='purge_pending'", (phase, key_id))
            handler = handlers.get(phase)
            if handler is None:
                raise RuntimeError(f"unknown purge phase {phase!r}")
            if self._block_phase and phase == self._block_phase:
                raise PurgeBlocked(
                    f"fault injection: purge blocked at phase {phase}")
            handler(key_id)
            if phase == PHASE_RESTORE:
                return

    def _record_purge_error(self, key_id: str, message: str) -> None:
        try:
            with self._lock:
                if self._closed or self._stop.is_set():
                    return
                self._conn.execute(
                    "UPDATE master_keys SET purge_error=?, "
                    "purge_attempts=purge_attempts+1 "
                    "WHERE key_id=? AND lifecycle='purge_pending'",
                    (message[:500], key_id))
        except Exception:
            pass

    def _phase_zero_material(self, key_id: str) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = self._get_key_row(cur, key_id)
                if row["state"] != "destroyed":
                    raise PurgeBlocked("key state is not destroyed")
                cur.execute(
                    "UPDATE master_keys SET key_material=zeroblob(32), "
                    "material_zeroed_at=COALESCE(material_zeroed_at, ?), "
                    "purge_phase=? WHERE key_id=?",
                    (time.time(), PHASE_SINGLE, key_id))
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def _sidecars(self) -> list[str]:
        return [self._db_path + s for s in SIDECAR_SUFFIXES]

    def _phase_single_file(self, key_id: str) -> None:
        """checkpoint 清除 WAL 历史帧，切 DELETE 日志模式准备单文件重建。

        journal_mode 切换在有其他连接持锁时会产生 SQLITE_BUSY。这里临时把
        busy_timeout 调小，让"清退受阻"尽快以 503 暴露，而不是把销毁请求
        拖到 SQLite 默认 30 秒超时；阶段已持久化，稍后自动重试。
        """
        with self._lock:
            if self._stop.is_set():
                raise PurgeInterrupted()
            self._conn.execute("PRAGMA busy_timeout=200")
            try:
                res = self._conn.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if res is not None and res[0]:
                    raise PurgeBlocked(
                        "wal_checkpoint busy; another reader is active")
                mode_row = self._conn.execute(
                    "PRAGMA journal_mode=DELETE").fetchone()
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                    raise PurgeBlocked(f"database locked: {exc}") from exc
                raise
            finally:
                try:
                    self._conn.execute("PRAGMA busy_timeout=30000")
                except sqlite3.Error:
                    pass
            mode = str(mode_row[0]).lower() if mode_row else ""
            if mode != "delete":
                raise PurgeBlocked(f"journal_mode switch returned {mode!r}")
            # DELETE 模式下 WAL 应已被 SQLite 移除；仍在则说明有活动连接
            if os.path.exists(self._db_path + "-wal"):
                raise PurgeBlocked("WAL file still present after mode switch")
            self._conn.execute(
                "UPDATE master_keys SET purge_phase=? WHERE key_id=?",
                (PHASE_COMPACT, key_id))

    def _phase_compacted(self, key_id: str) -> None:
        """VACUUM 重建整个库：所有空闲页/历史页被丢弃，旧材料不再在库内。"""
        with self._lock:
            if self._stop.is_set():
                raise PurgeInterrupted()
            self._conn.execute("PRAGMA temp_store=MEMORY")
            self._conn.execute("VACUUM")
            freelist = self._conn.execute("PRAGMA freelist_count").fetchone()[0]
            if freelist != 0:
                raise PurgeBlocked(f"freelist not empty after VACUUM ({freelist})")
            self._conn.execute(
                "UPDATE master_keys SET purge_phase=? WHERE key_id=?",
                (PHASE_SHRED, key_id))

    def _phase_shredded(self, key_id: str) -> None:
        """覆写并删除本库的 WAL/SHM/journal 旁路文件；主库保持完好。"""
        with self._lock:
            if self._stop.is_set():
                raise PurgeInterrupted()
            self._conn.close()
            try:
                for path in self._sidecars():
                    _shred_file(path, self._scrub_passes)
                # SQLite 的 master journal 形如 <db>-mj-<random>
                base = os.path.basename(self._db_path) + "-mj-"
                for name in os.listdir(self._db_dir):
                    if name.startswith(base):
                        _shred_file(os.path.join(self._db_dir, name),
                                    self._scrub_passes)
                _fsync_dir(self._db_dir)
            finally:
                self._conn = self._new_conn()
            self._conn.execute(
                "UPDATE master_keys SET purge_phase=? WHERE key_id=?",
                (PHASE_RESTORE, key_id))

    def _phase_restored(self, key_id: str) -> None:
        """回到 WAL，核验旧材料零残留后才置 purged。

        顺序保证：先 checkpoint(TRUNCATE) 把"已零化"的密钥行写进主库并清空
        WAL 中所有历史帧，之后才把 lifecycle 置 purged；因此 purged 落盘后
        WAL 里只可能有零化行/新信封等，不可能再出现旧密钥材料。
        """
        with self._lock:
            if self._stop.is_set():
                raise PurgeInterrupted()
            journal = self._db_path + "-journal"
            res = self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if res is not None and res[0]:
                raise PurgeBlocked("wal_checkpoint busy before purge verify")
            if os.path.exists(journal):
                raise PurgeBlocked("rollback journal still present after purge")
            integrity = self._conn.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise PurgeBlocked(f"integrity_check failed: {integrity}")
            row = self._conn.execute(
                "SELECT key_material, state FROM master_keys WHERE key_id=?",
                (key_id,)).fetchone()
            if row is None:
                raise PurgeBlocked("master key row disappeared")
            if row["state"] != "destroyed":
                raise PurgeBlocked("key state is not destroyed")
            material = bytes(row["key_material"])
            if len(material) != 32 or any(material):
                raise PurgeBlocked("key material is not fully zeroed")
            # 以上全部通过才落 purged；写入只会追加零化数据，不含旧材料
            self._conn.execute(
                "UPDATE master_keys SET purge_phase=?, lifecycle='purged', "
                "purge_verified_at=?, purge_error=NULL, purge_attempts=0 "
                "WHERE key_id=?",
                (PHASE_DONE, time.time(), key_id))
            verify = self._conn.execute(
                "SELECT lifecycle, purge_phase, key_material FROM master_keys "
                "WHERE key_id=?", (key_id,)).fetchone()
            if (verify is None or verify["lifecycle"] != "purged"
                    or verify["purge_phase"] != PHASE_DONE
                    or any(bytes(verify["key_material"]))):
                # 回退为可接续状态，让后台下一轮重新核验，绝不带着
                # 未核实的 purged 标记对外报告完成。
                self._conn.execute(
                    "UPDATE master_keys SET lifecycle='purge_pending', "
                    "purge_phase=? WHERE key_id=? AND lifecycle='purged'",
                    (PHASE_RESTORE, key_id))
                raise PurgeBlocked("post-purge verification failed")
            try:
                # 尽量把 WAL 清空，便于运维观察；busy 不影响正确性，因为
                # 此刻 WAL 中的所有帧都产生于零化 checkpoint 之后。
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass

    # ---- DEK 操作 -------------------------------------------------------
    def generate_dek(self) -> dict:
        """生成新 DEK，用当前主密钥包裹后返回（明文 DEK 同时返回一次，
        供 API 服务立即加密原片；API 不落盘明文 DEK）。"""
        with self._lock:
            cur = self._conn.cursor()
            current = self.current_key_id()
            if not current:
                raise KeyError_(409, "no_active_master",
                                "no active master key; bootstrap first")
            row = self._get_key_row(cur, current)
            if row["state"] != "active":
                raise KeyError_(409, "no_active_master",
                                f"current master key {current} is not active")
            dek = new_data_key()
            envelope = wrap_dek(row["key_material"], dek)
            return {"key_id": current, "dek": dek.hex(),
                    "wrapped_dek": envelope.hex()}

    def unwrap(self, key_id: str, wrapped_dek_hex: str) -> dict:
        with self._lock:
            cur = self._conn.cursor()
            row = self._get_key_row(cur, key_id)
            if row["state"] != "active":
                raise KeyError_(
                    410, "key_destroyed",
                    f"master key {key_id} has been destroyed "
                    f"(purge phase={row['purge_phase'] or 'done'})")
            try:
                dek = unwrap_dek(row["key_material"],
                                 bytes.fromhex(wrapped_dek_hex))
            except Exception as exc:  # 认证失败 / 格式错误
                raise KeyError_(400, "unwrap_failed", str(exc)) from exc
            return {"dek": dek.hex()}

    def rewrap(self, old_key_id: str, wrapped_dek_hex: str,
               token: Optional[str]) -> dict:
        """把旧 MK 包裹的 DEK 改用当前 MK 包裹，不暴露明文 DEK 给调用方。
        幂等：同一 token 的重试返回首次结果。"""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                if token:
                    cached = cur.execute(
                        "SELECT response FROM idem_log WHERE token=?", (token,)
                    ).fetchone()
                    if cached is not None:
                        cur.execute("COMMIT")
                        import json
                        return {**json.loads(cached["response"]),
                                "idempotent": True}
                old = self._get_key_row(cur, old_key_id)
                if old["state"] != "active":
                    raise KeyError_(
                        410, "key_destroyed",
                        f"master key {old_key_id} has been destroyed")
                new_key_id = cur.execute(
                    "SELECT current_key_id FROM meta WHERE id=1"
                ).fetchone()["current_key_id"]
                if not new_key_id:
                    raise KeyError_(409, "no_active_master",
                                    "no active master key")
                new = self._get_key_row(cur, new_key_id)
                if new["state"] != "active":
                    raise KeyError_(409, "no_active_master",
                                    "current master key is not active")
                try:
                    dek = unwrap_dek(old["key_material"],
                                     bytes.fromhex(wrapped_dek_hex))
                except Exception as exc:
                    raise KeyError_(400, "unwrap_failed", str(exc)) from exc
                new_envelope = wrap_dek(new["key_material"], dek)
                result = {"old_key_id": old_key_id, "key_id": new_key_id,
                          "wrapped_dek": new_envelope.hex()}
                if token:
                    import json
                    cur.execute(
                        "INSERT OR IGNORE INTO idem_log "
                        "(token, status_code, response, created_at) "
                        "VALUES (?,?,?,?)",
                        (token, 200, json.dumps(result), time.time()),
                    )
                cur.execute("COMMIT")
                return result
            except Exception:
                try:
                    cur.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    def close(self):
        self._stop.set()
        self._wake.set()
        thread = getattr(self, "_purge_thread", None)
        if thread is not None and thread.is_alive():
            thread.join(timeout=15)
        with self._lock:
            if not self._closed and (thread is None or not thread.is_alive()):
                self._closed = True
                self._conn.close()
