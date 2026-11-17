# 运维与故障处理手册

## 1. 部署清单

| 组件 | 镜像 | 持久卷 | 暴露 |
|---|---|---|---|
| image-api | microscopy/image-api:1.0.0 | api-data（metadata.db + blobs/） | 8000 |
| keystore | microscopy/keystore:1.0.0 | keystore-data（keystore.db） | 127.0.0.1:8001 |

两个容器必须配置相同的 `KEY_SERVICE_TOKEN`。密钥服务端口只绑回环地址，
不应对仪器网段或公网暴露。

## 2. 数据与密钥位置

- 主密钥材料：仅 `keystore-data` 卷内 SQLite 的 `master_keys.key_material`。
  销毁分两段：先零覆写并把 `state` 置 `destroyed`（此后 `unwrap/rewrap` 一律
  410），再把本卷数据库与 WAL/SHM/回滚日志中的旧材料清退并核实，最后置
  `lifecycle='purged'`。只有 `purged` 才报告销毁完成。
- 数据密钥：永远以 64 字节信封（`MAGIC|nonce|ct|tag`）存在 api-data 的
  `images.wrapped_dek`；明文 DEK 只在 API 单次请求内存中出现。
- 原片：api-data 的 `blobs/*.msef`，全部为 AES-256-GCM 分帧密文；
  明文不落盘（multipart 假脱机已在代码中禁用）。

备份策略：两卷需**一起**备份。单独备份 api-data 在旧 MK 销毁后无法解读；
单独备份 keystore-data 没有原片。建议离线备份 keystore-data 并严格限制访问。

## 3. 标准轮换流程

```bash
curl -X POST -H 'Content-Type: application/json' -d '{"confirm":true}' \
  http://localhost:8000/rotations
# 轮询 GET /rotations/{job_id}，state 终态：completed / failed
```

状态机：`migrating`（逐信封 rewrap，blob 正文不动）→ `destroying`
（零残留核验 + 销毁旧 MK + 等密钥服务清退核实）→ `completed`。
进行中再次发起轮换返回 409。作业失败时先查 `error` 字段，修复后
（通常是密钥服务暂时不可达）重启 API 即可自动接续，无需手工干预。

### 3.1 销毁完成判定（清退缺口修复）

密钥服务把销毁拆成**提交**与**清退**两步，`GET /internal/master/status`
中每个密钥同时给出 `state` 与 `lifecycle`：

| state | lifecycle | 含义 | unwrap/rewrap | destroy 接口 |
|---|---|---|---|---|
| active | active | 正常可用 | 允许 | — |
| destroyed | purge_pending | 已不可用，清退未核实 | 410 | 503 `key_purge_blocked` |
| destroyed | purged | 材料已从库/WAL/SHM/journal 清退并核实 | 410 | 200（幂等） |

清退阶段持久化在 `master_keys.purge_phase`，按
`zero_material → single_file → compacted → shredded → restored` 推进：

1. `zero_material`：再次确认 `key_material` 为 32 个零字节；
2. `single_file`：`wal_checkpoint(TRUNCATE)` 后切 DELETE 日志模式，
   把旧 WAL 历史帧落盘并移除；
3. `compacted`：`VACUUM` 重建整个库，丢弃全部空闲页/历史页；
4. `shredded`：关闭连接，对 WAL/SHM/journal 旁路文件多遍覆写、截断、
   删除并 fsync 目录（主库已重建，不复删）；
5. `restored`：重新打开为 WAL，`integrity_check` + 复核密钥列为零 +
   旁路文件无残留，最后置 `lifecycle=purged`。

API 轮换作业只有在密钥服务返回 `lifecycle=purged` 后才置 `completed`；
`GET /rotations/{job_id}` 同时给出 `purge_confirmed`。503 期间作业停在
`destroying`（`error` 说明当前阶段），后台退避重试，API/密钥服务重启都会
从持久化阶段继续，**绝不提前报完成**。旧密钥在整个 `purge_pending` 期间
解包/改包均为 410；新入湖与已改包原片不受影响。

排查命令：

```bash
# 未完成清退的密钥与阶段
curl -sS -H "X-Key-Service-Token: $TOKEN" \
  http://127.0.0.1:8001/internal/purge/pending
# 轮换作业当前状态与错误
curl -sS http://localhost:8000/rotations/latest
```

## 4. 故障演练开关（keystore）

- `KEY_OP_DELAY=<秒>`：模拟慢密钥服务，验证在线流量不被轮换拖死。
- `KEY_DESTROY_DROP_RECEIPT=true`：销毁**与清退均已完成**后丢弃 HTTP 回执，
  验证 API 自动重试 + 只读状态核实、作业仍如实报 completed。
- `KEY_PURGE_BLOCK_PHASE=<阶段>`：指定清退阶段总是失败（可接续），验证
  destroy 返回 503、作业停在 destroying 不报 completed；解除并重启后继续。
- `KEY_PURGE_WAIT_SECONDS=<秒>`：destroy 等待清退核实的时长，超时 503。
- `KEY_PURGE_SCRUB_PASSES=<n>`：旁路文件覆写遍数（默认 3）。

```bash
# 演练清理受阻 + 重启接续
KEY_PURGE_BLOCK_PHASE=compacted docker compose up --build keystore
# 解除：去掉该变量重启 keystore，轮换作业会自动续退到 completed
```

## 5. 崩溃/重启语义

| 场景 | 行为 |
|---|---|
| API 在上传中崩溃 | 重启后该件标 `failed`（不晚发布）；blob 残片可按 failed 行清理 |
| API 在轮换中崩溃 | 重启后后台线程自动接续未完成作业到终态 |
| 崩溃于"MK 已切换、作业未建"窗口 | 启动对账自动补建迁移作业 |
| 崩溃于"旧 MK 已销毁、清退未核实" | 启动对账补建 destroying 作业，密钥服务从 `purge_phase` 续退，核实后才 completed |
| 密钥服务在清退途中崩溃/被 kill | 阶段已持久化；重启后台线程自动继续（幂等重放当前阶段） |
| 密钥服务重启 | 主密钥从卷内 SQLite 恢复，已入湖原片逐字节可读 |
| 销毁回执丢失 | KeyClient 重试并以 `/internal/master/status` 只读核实，且要求 `lifecycle=purged` |
| 清退受阻（卷被其他连接占用等） | destroy 返回 503，作业保留 destroying 并退避重试，不报 completed |

## 6. 已知限制（单实例/SQLite 范围之外）

1. 单实例：API 与密钥服务均为单节点，无水平扩展与高可用；多实例需要
   分布式轮换锁（如 Postgres 行锁/etcd）与共享对象存储。
2. 内部服务间为共享 Bearer 令牌；生产化建议改 mTLS 并加调用审计。
3. 根密钥目前为软件随机生成并存于 SQLite；更高合规要求应替换为 HSM/KMS，
   本服务的信封接口（generate/unwrap/rewrap）保持不变即可适配。
4. GCM 帧验签失败发生在流式响应开始之后，表现为连接中断（HTTP 流无法
   再改状态码）；客户端应将不完整响应当作失败，可重新 GET 重试。
5. 销毁 MK 是不可逆操作；销毁前系统保证无 ready/receiving 行依赖它，
   但 failed 历史行的信封将永久无法解包（这些原片本就不可读）。
6. 清退在单进程内串行执行：同一时刻只处理一把待清退密钥。若 `single_file`
   阶段持续被其他连接占用（503），需先移除占用者（例如直接打开旧库的
   外部工具），后台会自动重试。正常单实例部署不会出现。
7. 文件系统层面：清退保证逻辑零残留（密钥列零化、库经 VACUUM 重建、
   WAL/SHM/journal 覆写删除）。底层 SSD/写时复制存储的物理块是否被覆写
   取决于存储固件；更高合规要求应使用支持加密擦除的自加密盘或 HSM。
