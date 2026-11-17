"""主密钥轮换后台工作线程。

状态机（状态持久化在 rotation_jobs，进程重启可接续）：
  migrating  ->  逐行 rewrap 信封（不重写图像密文正文）
  destroying ->  确认零残留后销毁旧主密钥；必须核实密钥服务已把持久卷
                 数据库与 WAL/日志文件中的旧密钥材料清退（lifecycle=purged）
                 才置 completed。清退受阻/中断时作业留在 destroying，
                 后台继续重试，重启后自动接续。
  completed / failed

并发生态保证：
  * 全程不持锁阻塞下载/上传；慢下载解包走旧 MK（销毁前完成解包即不受影响），
    下载中的帧解密只在本进程内存用明文 DEK，与密钥服务无关；
  * rewrap 用条件 UPDATE（WHERE master_key_id=旧），迟到的在途上传若已自行
    改绑新 MK 则自动跳过；
  * 销毁前再扫一遍残留并补迁，确保不会有原片依赖已销毁密钥；
  * 同一时刻只允许一个轮换作业（DB 约束 + 启动校验）；
  * 常驻线程每秒轮询未完成作业，进程重启后自动接续，不依赖唤醒信号。
"""
from __future__ import annotations

import asyncio
import os
import threading
import time
import traceback

from .keyclient import KeyClient, KeyServiceError
from .metadata import MetadataDB

POLL_INTERVAL = 1.0
BATCH_PAUSE = 0.02           # 批次间让出，避免挤占在线流量
RETRY_BUDGET = 6             # 单作业内瞬时错误总重试预算
# 销毁/清退是幂等且可接续的：受阻时不应把作业判死，而是留在 destroying
# 持续重试（API 重启后也会继续）。此上限只用于防止永久静默重试。
DESTROY_RETRY_BUDGET = int(os.environ.get("DESTROY_RETRY_BUDGET", "0")) or None
# 超过此时长仍处于 receiving 的上传视为僵死（崩溃残留由启动恢复处理，
# 这里兜底处理连接挂起），判失败以解除对轮换销毁阶段的阻塞。
UPLOAD_STALE_SECONDS = float(os.environ.get("UPLOAD_STALE_SECONDS", "3600"))


class RotationWorker:
    def __init__(self, db: MetadataDB, keys: KeyClient,
                 loop: asyncio.AbstractEventLoop):
        self._db = db
        self._keys = keys
        self._loop = loop
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._thread_main, daemon=True,
                                        name="rotation-worker")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _thread_main(self):
        try:
            fut = asyncio.run_coroutine_threadsafe(self._run(), self._loop)
            fut.result()
        except Exception:
            traceback.print_exc()

    async def _run(self):
        """常驻协程：发现未完成作业就驱动到终态，然后继续轮询。"""
        while not self._stop.is_set():
            job = self._db.active_rotation()
            if job is not None:
                await self._drive_job(job["job_id"])
            else:
                await asyncio.sleep(POLL_INTERVAL)

    async def _drive_job(self, job_id: str):
        retries = 0
        destroy_retries = 0
        while not self._stop.is_set():
            job = self._db.get_rotation(job_id)
            if job is None or job["state"] in ("completed", "failed"):
                return
            try:
                if job["state"] == "migrating":
                    done = await self._migrate(job)
                    retries = 0
                    if done:
                        self._db.bump_rotation(job_id, state="destroying")
                    else:
                        await asyncio.sleep(POLL_INTERVAL)
                elif job["state"] == "destroying":
                    if await self._destroy(job):
                        return
                    # 销毁已生效但清退未核实：留在 destroying 持续重试，
                    # 绝不报 completed，也不把可接续状态判死。
                    destroy_retries += 1
                    if (DESTROY_RETRY_BUDGET
                            and destroy_retries >= DESTROY_RETRY_BUDGET):
                        self._db.bump_rotation(
                            job_id, error="destroy purge still blocked after "
                                          f"{destroy_retries} attempts; "
                                          "job remains resumable")
                        await asyncio.sleep(POLL_INTERVAL)
                    await asyncio.sleep(min(0.5 * 2 ** min(destroy_retries, 4),
                                            8.0))
            except KeyServiceError as exc:
                if job["state"] == "destroying" and exc.status_code in (503, 429):
                    # 清退受阻/密钥服务暂不可用：销毁已提交且幂等，作业留在
                    # destroying 稍后重试，绝不提前报 completed。
                    self._db.bump_rotation(
                        job_id, error=f"destroy pending, will retry: "
                                      f"{exc.code} {exc.message}")
                    destroy_retries += 1
                    await asyncio.sleep(min(0.5 * 2 ** min(destroy_retries, 4),
                                            8.0))
                    continue
                retries += 1
                if retries >= RETRY_BUDGET:
                    self._db.bump_rotation(
                        job_id, state="failed",
                        error=f"key service error after retries: "
                              f"{exc.code} {exc.message}")
                    return
                await asyncio.sleep(min(0.5 * (2 ** retries), 8.0))
            except Exception as exc:  # 防御：任何意外都落 failed，不静默
                self._db.bump_rotation(job_id, state="failed",
                                       error=f"unexpected: {exc!r}")
                traceback.print_exc()
                return

    async def _migrate(self, job: dict) -> bool:
        """扫描绑定旧 MK 的行并 rewrap。返回 True 表示零残留可进入销毁。"""
        old_key, job_id = job["old_key_id"], job["job_id"]
        migrated_now = 0
        for row in self._db.iter_under_key(old_key):
            latest = self._db.get_rotation(job_id)
            if latest is None or latest["state"] == "failed":
                return False
            # 在途上传分两种：
            #  1) 僵死（超时）-> 判失败，禁止晚发布，解除销毁阻塞
            #  2) 活跃 -> 跳过，本轮先迁移别的；下轮再看（最终成功的上传会在
            #     finalize 时改绑当前新 MK；失败的不会成为可读原片）
            if row["status"] == "receiving":
                if time.time() - row["created_at"] > UPLOAD_STALE_SECONDS:
                    self._db.fail_image(
                        row["image_id"],
                        "stale receiving upload during key rotation")
                    self._db.bump_rotation(job_id, migrated=1)
                    migrated_now += 1
                continue
            try:
                token = f"{job_id}:{row['image_id']}"
                res = await self._keys.rewrap(old_key, row["wrapped_dek"], token)
            except KeyServiceError as exc:
                if exc.status_code == 410:
                    # 旧 MK 已被销毁而仍有行依赖它：这些原片已无法改包/读取。
                    # 这是不可恢复的数据完整性事件，作业如实判失败并保留原因，
                    # 不再无限重试（密钥服务的清退线程会独立完成清退）。
                    self._db.bump_rotation(
                        job_id, failed=1, state="failed",
                        error="old key destroyed with rows remaining: "
                              f"{exc.message}")
                    return False
                raise
            changed = self._db.rewrap_row(row["image_id"], old_key,
                                          res["key_id"], res["wrapped_dek"])
            if changed:
                migrated_now += 1
                self._db.bump_rotation(job_id, migrated=1)
            if migrated_now and migrated_now % 50 == 0:
                await asyncio.sleep(BATCH_PAUSE)

        # 最终核验：在途上传可能在扫描后又落了一行旧 MK，下轮继续补迁到零残留
        return self._db.count_under_key(old_key, only_migratable=True) == 0

    async def _destroy(self, job: dict) -> bool:
        """销毁旧 MK 并核实材料已清退。返回 True 仅当可置 completed。"""
        old_key, job_id = job["old_key_id"], job["job_id"]
        # 销毁前最后一次核实（防扫描窗口内的迟到行）
        if self._db.count_under_key(old_key, only_migratable=True) != 0:
            self._db.bump_rotation(job_id, state="migrating")
            return False
        try:
            # 销毁；回执丢失时 KeyClient 内部以只读状态核实；清退未核实
            # 时密钥服务返回 503，这里保留 destroying 稍后重试。
            await self._keys.destroy_master(old_key)
        except KeyServiceError as exc:
            if exc.status_code in (503, 429):
                self._db.bump_rotation(
                    job_id,
                    error=f"destroy committed, key material purge still "
                          f"pending: {exc.code} {exc.message}")
                return False
            raise
        # 二次核实：密钥服务视角必须 lifecycle=purged（销毁 + 清退核实），
        # 仅有 state=destroyed 不足以证明 WAL/日志/空闲页已无旧密钥材料。
        status = await self._keys.master_status()
        entry = next((k for k in status.get("keys", [])
                      if k["key_id"] == old_key), None)
        if entry is None or entry.get("lifecycle") != "purged":
            lifecycle = None if entry is None else entry.get("lifecycle")
            self._db.bump_rotation(
                job_id,
                error=f"destroy completed but key material purge not verified "
                      f"(lifecycle={lifecycle}); will re-check")
            return False
        self._db.bump_rotation(job_id, state="completed", error="")
        return True
