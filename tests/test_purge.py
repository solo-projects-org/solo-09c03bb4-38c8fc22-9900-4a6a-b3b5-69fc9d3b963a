"""销毁清退：密钥材料必须从持久卷数据库及 WAL/日志文件清退后才算完成。

关键不变量：
  * destroy 已生效（state=destroyed）但 lifecycle != purged 时：
      - unwrap/rewrap 必须 410（旧密钥不能解包）；
      - destroy 接口必须 503，不得报成功；
      - 阶段持久化，重启后继续，最终 reached purged；
  * 恢复后：新入湖/已改包原片照常可读，轮换作业完成后才报 completed。
"""
from __future__ import annotations

import os
import sqlite3
import sys
import time
from pathlib import Path

from conftest import _download, _key_headers, _upload, _wait_rotation

ROOT = Path(__file__).resolve().parents[1]


def _import_keystore_storage():
    """导入密钥服务的持久化层（两个服务包都叫 app，这里精确指定 keystore）。"""
    key_dir = str(ROOT / "keystore")
    for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
        del sys.modules[name]
    if key_dir not in sys.path:
        sys.path.insert(0, key_dir)
    import importlib
    return importlib.import_module("app.storage")


def _scan_leaks(key_db_path: str, raw: bytes) -> list[str]:
    """返回持久卷上仍含旧密钥明文字节的文件后缀列表。"""
    found = []
    for suffix in ("", "-wal", "-shm", "-journal"):
        path = key_db_path + suffix
        if os.path.exists(path):
            with open(path, "rb") as fh:
                if raw in fh.read():
                    found.append(suffix or "db")
    return found


def _raw_key_bytes(stack) -> tuple[str, bytes]:
    """当前主密钥 id 与材料（仅测试直接读密钥卷用于验证清退）。"""
    conn = sqlite3.connect(stack["key_db"])
    row = conn.execute(
        "SELECT key_id, key_material FROM master_keys "
        "WHERE state='active'").fetchone()
    conn.close()
    return row[0], bytes(row[1])


def _set_keystore_env(stack, **updates) -> None:
    env = dict(stack["keys"]._env)
    env.update({k: v for k, v in updates.items()})
    stack["keys"].stop()
    stack["keys"]._env = env
    stack["keys"].start()


def test_destroy_purges_wal_and_key_material_before_reporting(stack):
    """正常销毁：完成后卷上任何文件都不再含旧密钥材料，且不会再解包。"""
    client = stack["client"]
    _upload(client, b"purge-normal", image_id="pn-1")
    old_key, raw = _raw_key_bytes(stack)
    job = client.post("/rotations", json={"confirm": True}).json()
    assert job["old_key_id"] == old_key
    result = _wait_rotation(client, job["job_id"])
    assert result["state"] == "completed", result
    assert result["purge_confirmed"] is True

    # 只在轮换完成后扫：正常路径不得把旧材料留在库/WAL/SHM/journal 里
    assert _scan_leaks(stack["key_db"], raw) == []

    st = stack["key_client"].get("/internal/master/status",
                                 headers=_key_headers()).json()
    entry = next(k for k in st["keys"] if k["key_id"] == old_key)
    assert entry["state"] == "destroyed" and entry["lifecycle"] == "purged"

    # 旧密钥不能再解包；新原片与已改包原片继续正常入仓取数
    r = stack["key_client"].post(
        "/internal/dek/unwrap",
        json={"key_id": old_key, "wrapped_dek": "00" * 64},
        headers=_key_headers())
    assert r.status_code == 410
    assert _download(client, "pn-1") == b"purge-normal"
    assert _upload(client, b"after-purge", image_id="pn-2").status_code == 201
    assert _download(client, "pn-2") == b"after-purge"


def test_purge_blocked_reports_not_completed_then_resumes_after_restart(stack):
    """清理受阻：destroy 报 503、作业不报 completed；解除后重启继续清退。"""
    client = stack["client"]
    _upload(client, b"blocked-body", image_id="pb-1")
    env = dict(stack["keys"]._env)
    env["KEY_PURGE_BLOCK_PHASE"] = "compacted"
    env["KEY_PURGE_WAIT_SECONDS"] = "0.5"
    stack["keys"].stop()
    stack["keys"]._env = env
    stack["keys"].start()
    old_key, raw = _raw_key_bytes(stack)

    job = client.post("/rotations", json={"confirm": True}).json()
    assert job["old_key_id"] == old_key
    # 清退受阻：一段时间内作业必须停在 destroying，绝不报 completed
    deadline = time.time() + 8
    seen = set()
    while time.time() < deadline:
        cur = client.get(f"/rotations/{job['job_id']}").json()
        seen.add(cur["state"])
        assert cur["state"] != "completed", cur
        time.sleep(0.3)
    assert "destroying" in seen, seen
    cur = client.get(f"/rotations/{job['job_id']}").json()
    assert cur["state"] == "destroying"
    assert cur["purge_confirmed"] is False
    assert cur["error"] and "purge" in cur["error"].lower()

    # 旧密钥已不可解包；WAL 中的旧材料可能仍在（清理受阻的预期可接续状态）
    r = stack["key_client"].post(
        "/internal/dek/unwrap",
        json={"key_id": old_key, "wrapped_dek": "00" * 64},
        headers=_key_headers())
    assert r.status_code == 410
    st = stack["key_client"].get("/internal/master/status",
                                 headers=_key_headers()).json()
    entry = next(k for k in st["keys"] if k["key_id"] == old_key)
    assert entry["state"] == "destroyed"
    assert entry["lifecycle"] == "purge_pending"
    assert entry["purge_phase"] == "compacted"

    # 新入湖照常走新 MK，已改包原片照常可读（不受清退受阻影响）
    assert _upload(client, b"while-blocked", image_id="pb-2").status_code == 201
    assert _download(client, "pb-1") == b"blocked-body"
    assert _download(client, "pb-2") == b"while-blocked"

    # 解除故障并重启密钥服务：从持久化阶段接续清退，作业随后 completed
    _set_keystore_env(stack, KEY_PURGE_BLOCK_PHASE="")
    result = _wait_rotation(client, job["job_id"], timeout=60)
    assert result["state"] == "completed", result
    assert result["purge_confirmed"] is True
    assert _scan_leaks(stack["key_db"], raw) == []
    # 期间轮换作业未完成时不允许开始下一次轮换
    assert _download(client, "pb-2") == b"while-blocked"


def test_purge_pending_resumes_after_keystore_crash(stack):
    """清退途中进程被终止：重启后从持久化阶段继续，最终核实并报完成。"""
    client = stack["client"]
    _upload(client, b"crash-body", image_id="pc-1")
    _set_keystore_env(stack, KEY_PURGE_BLOCK_PHASE="compacted",
                      KEY_PURGE_WAIT_SECONDS="0.5")
    old_key, raw = _raw_key_bytes(stack)
    job = client.post("/rotations", json={"confirm": True}).json()

    # 等作业进入 destroying 且密钥服务记录 purge_pending
    deadline = time.time() + 30
    phase = None
    while time.time() < deadline:
        st = stack["key_client"].get("/internal/master/status",
                                     headers=_key_headers()).json()
        entry = next(k for k in st["keys"] if k["key_id"] == old_key)
        if entry["lifecycle"] == "purge_pending" and entry["purge_phase"]:
            phase = entry["purge_phase"]
            break
        time.sleep(0.2)
    assert phase == "compacted", phase
    assert client.get(f"/rotations/{job['job_id']}").json()["state"] == "destroying"

    # 直接终止密钥服务（模拟进程中断），再以不再注入故障的方式重启
    stack["keys"].stop()
    stack["keys"]._env = {**stack["keys"]._env, "KEY_PURGE_BLOCK_PHASE": "",
                          "KEY_PURGE_WAIT_SECONDS": "10"}
    stack["keys"].start()

    result = _wait_rotation(client, job["job_id"], timeout=60)
    assert result["state"] == "completed", result
    assert _scan_leaks(stack["key_db"], raw) == []
    assert _download(client, "pc-1") == b"crash-body"

    # 重启 API 后：已入湖数据仍可读、仍可新入湖，轮换作业保持 completed
    stack["api"].restart()
    assert client.get(f"/rotations/{job['job_id']}").json()["state"] == "completed"
    assert _download(client, "pc-1") == b"crash-body"
    assert _upload(client, b"post-crash", image_id="pc-2").status_code == 201
    assert _download(client, "pc-2") == b"post-crash"


def test_destroy_api_reports_503_while_purge_blocked(stack):
    """直接调用密钥服务：清退受阻时 destroy 返回 503（不报销毁完成）。"""
    kc = stack["key_client"]
    _set_keystore_env(stack, KEY_PURGE_BLOCK_PHASE="shredded",
                      KEY_PURGE_WAIT_SECONDS="0.5")
    rot = kc.post("/internal/master/rotate", headers=_key_headers()).json()
    old_key = rot["old_key_id"]
    r = kc.post("/internal/master/destroy", json={"key_id": old_key},
                headers=_key_headers())
    assert r.status_code == 503, r.text
    assert r.json()["detail"]["code"] == "key_purge_blocked"
    st = kc.get("/internal/master/status", headers=_key_headers()).json()
    entry = next(k for k in st["keys"] if k["key_id"] == old_key)
    assert entry["state"] == "destroyed" and entry["lifecycle"] == "purge_pending"
    assert entry["purge_phase"] == "shredded"
    pending = kc.get("/internal/purge/pending", headers=_key_headers()).json()
    assert any(p["key_id"] == old_key for p in pending["pending"])
    # 解包仍 410
    assert kc.post("/internal/dek/unwrap",
                   json={"key_id": old_key, "wrapped_dek": "00" * 64},
                   headers=_key_headers()).status_code == 410
    # 解除后重试 destroy 幂等完成
    _set_keystore_env(stack, KEY_PURGE_BLOCK_PHASE="")
    deadline = time.time() + 30
    while time.time() < deadline:
        st = kc.get("/internal/master/status", headers=_key_headers()).json()
        entry = next(k for k in st["keys"] if k["key_id"] == old_key)
        if entry["lifecycle"] == "purged":
            break
        time.sleep(0.2)
    assert entry["lifecycle"] == "purged"
    again = kc.post("/internal/master/destroy", json={"key_id": old_key},
                    headers=_key_headers())
    assert again.status_code == 200
    assert again.json()["idempotent"] is True


def test_upgrade_purges_legacy_destroyed_key_left_in_wal(tmp_path):
    """旧版本升级：旧代码只做行内零覆写，WAL 里还留着完整旧密钥；新版本在
    启动后必须自动把这条遗留材料清退掉，且不再解包。"""
    storage = _import_keystore_storage()
    db_path = str(tmp_path / "legacy.db")
    raw = os.urandom(32)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE master_keys (key_id TEXT PRIMARY KEY,
            key_material BLOB NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('active','destroyed')),
            created_at REAL NOT NULL, destroyed_at REAL);
        CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK (id=1),
            current_key_id TEXT);
        INSERT OR IGNORE INTO meta (id,current_key_id) VALUES (1,NULL);
        CREATE TABLE idem_log (token TEXT PRIMARY KEY,
            status_code INTEGER NOT NULL, response TEXT NOT NULL,
            created_at REAL NOT NULL);
    """)
    old = "mk-legacy-destroyed"
    conn.execute("INSERT INTO master_keys VALUES (?,?, 'active', ?, NULL)",
                 (old, raw, time.time()))
    conn.execute("INSERT INTO master_keys VALUES (?,?, 'active', ?, NULL)",
                 ("mk-legacy-current", os.urandom(32), time.time()))
    conn.execute("UPDATE meta SET current_key_id='mk-legacy-current'")
    conn.commit()
    assert raw in Path(db_path + "-wal").read_bytes()
    # 模拟旧代码的销毁：只零化行内材料，WAL 历史帧仍在
    conn.execute("UPDATE master_keys SET key_material=?, state='destroyed', "
                 "destroyed_at=? WHERE key_id=?", (b"\x00" * 32, time.time(), old))
    conn.commit()
    assert raw in Path(db_path + "-wal").read_bytes()
    conn.close()

    os.environ["KEY_PURGE_WAIT_SECONDS"] = "5"
    try:
        store = storage.KeyStore(db_path)
        try:
            deadline = time.time() + 20
            entry = None
            while time.time() < deadline:
                entry = next(k for k in store.status()["keys"]
                             if k["key_id"] == old)
                if entry["lifecycle"] == "purged":
                    break
                time.sleep(0.05)
            assert entry["lifecycle"] == "purged", entry
            assert _scan_leaks(db_path, raw) == []
            try:
                store.unwrap(old, "00" * 64)
                raise AssertionError("legacy key must not unwrap")
            except storage.KeyError_ as exc:
                assert exc.status_code == 410
            assert store.generate_dek()["key_id"] == "mk-legacy-current"
        finally:
            store.close()
    finally:
        os.environ.pop("KEY_PURGE_WAIT_SECONDS", None)
