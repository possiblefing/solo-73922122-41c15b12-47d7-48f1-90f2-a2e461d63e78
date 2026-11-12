# 并发密码猜测限制登录服务

FastAPI + SQLite(WAL) + argon2-cffi 实现的登录演示：两个独立 Web 进程共享同一
SQLite 数据库，对同一员工账号的并发密码猜测做严格名额控制，**客户端断连不能绕过限制**。

## 快速启动（Docker Compose）

```bash
docker compose up --build
```

启动后浏览器打开：

| 入口 | 地址 | 说明 |
| --- | --- | --- |
| 主入口（Nginx 轮询两个进程） | http://localhost:8080 | 推荐，请求在 web1/web2 间轮询 |
| 直连进程 1 | http://localhost:8001 | 响应头 `X-Served-By: web1` |
| 直连进程 2 | http://localhost:8002 | 响应头 `X-Served-By: web2` |

预置账号（数据库中**只存 argon2id 哈希**，页面上展示明文仅为演示方便）：

- `alice` / `alice-pass-2026`
- `bob` / `bob-pass-2026`

停止与清理：

```bash
docker compose down          # 停止；命名卷 login-db 保留，窗口错误持久存在
docker compose down -v       # 连数据库卷一起删除，下次启动重新预置
```

## 规则与实现映射

| 需求 | 实现 |
| --- | --- |
| 每账号 60 秒窗口错误数 + 在途核验数合计 ≤ 5 | `app/db.py:acquire_slot`，`BEGIN IMMEDIATE` 短事务内同时计数 `login_errors`（窗口内）与 `login_inflight`，超限直接拒绝 |
| 核验前原子占位 | 计数与插入占位在同一个 SQLite 写事务中完成；WAL + `busy_timeout=30s` 保证两进程竞争时串行裁决、不报错 |
| 满额立即 429 且不算哈希 | 占位失败直接抛 `HTTPException(429)`，带 `Retry-After`；argon2 调用在其后，根本不会执行（测试实测 429 响应约 0.02s 返回） |
| 完成后释放占位；错误按完成时刻计数 | `app/db.py:settle` 在核验结束后统一结算，错误记录写的是结算时刻 `time.time()`，不是占位时刻 |
| 成功清除**当时已完成**错误，其他在途之后出错仍计数 | 成功事务只 `DELETE login_errors`，不碰 `login_inflight`；慢请求结束后照常插入自己的错误（集成测试第 7 组覆盖） |
| 结算与会话签发一起提交 | 释放占位 / 清错误或插错误 / 插入 session 行在同一事务，同生共死 |
| 两个 Web 进程共用状态 | 两容器挂载同一命名卷的同一个 `login.db`，WAL 模式允许读写并发、写事务互斥裁决 |
| 哈希计算不持数据库写锁 | `verify_password` 在 `app/main.py` 登录处理中、任何写事务之外执行；DB 连接在核验前就已关闭 |
| 不用全局锁串行核验 | 无任何进程内锁；同步端点跑在 Starlette 线程池（上限调到 64），argon2 完全并行，协调只靠 SQLite 短事务 |
| 断连仍完成核验并结算，不提前归还名额 | 登录端点是同步 `def`，占位到结算之间无 `await` 点，客户端断开无法取消线程；核验和结算必然先完成（集成测试第 6 组覆盖） |
| 重启保留窗口内错误、清理未完成占位 | 错误是已提交的普通行；启动钩子 `init_db` 无条件 `DELETE FROM login_inflight`（旧核验者已随进程死亡） |
| 随机 HttpOnly 会话 | `secrets.token_urlsafe(32)` 生成 256-bit 令牌，Cookie 带 `HttpOnly; SameSite=Lax`，仅令牌哈希引用以行存于 `sessions` 表 |

## 数据库结构（SQLite，WAL）

```text
accounts        id, username UNIQUE, password_hash(argon2id), created_at
login_errors    account_id, created_at          -- 按完成时刻记录，窗口外惰性清理
login_inflight  slot_id PK, account_id, acquired_at  -- 原子占位，重启清空
sessions        token PK, account_id, created_at, expires_at
```

## HTTP 接口

- `GET /` — 演示网页（并发发起、AbortController 中途断开、1 秒刷新各账号剩余名额、可调核验延迟）
- `POST /api/login` — body `{username, password, delay}`，成功 200 并下发会话 Cookie；失败 401；满额 429（`Retry-After`）
- `GET /api/me` — 查看当前登录身份
- `POST /api/logout` — 销毁当前会话
- `GET /api/stats` — 每个账号的窗口错误数、在途数、剩余名额

所有响应带 `X-Served-By`（web1/web2）与 `X-Process-Time-ms`，便于观察轮询与耗时。

## 网页演示建议

1. 对 `alice` 并发发起 6 个错误密码、延迟 4s：前 5 个进入在途，第 6 个立即 429。
2. 在途期间点「全部断开」：浏览器侧已取消，名额表仍显示 5 在途；约 4s 后服务端自行结算，在途归零、错误变 5。
3. 5 个错误结算后任何请求（哪怕密码正确）都立即 429；等待窗口滑过自动恢复。
4. 用正确密码发一个长延迟请求，同时并发错误请求，观察「成功只清已完成错误、后到的在途错误仍计数」。
5. `docker compose restart` 后观察：窗口错误还在、在途占位被清空。

## 本地无 Docker 时运行（开发/测试）

```bash
pip install -r requirements.txt
export LOGIN_DB_PATH=/tmp/login.db
uvicorn app.main:app --port 8001   # 终端 A
PROCESS_NAME=web2 uvicorn app.main:app --port 8002   # 终端 B，同一 DB 文件
```

## 集成测试

`tests/run_integration.py` 会在本机拉起两个共享同一 SQLite 文件的 uvicorn 进程，
覆盖 10 组共 39 项断言（原子占位/429 不哈希、滑窗、断连结算、交错完成、
重启语义、无明文存储、服务日志无异常等）：

```bash
python tests/run_integration.py
```

测试通过环境变量 `ERROR_WINDOW_SECONDS` / `MAX_SLOTS` 把窗口缩短为 5 秒以便验证，
生产默认值为 60 秒 / 5。

## 可调环境变量

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `LOGIN_DB_PATH` | `/data/login.db` | SQLite 文件路径（两进程必须指向同一文件） |
| `ERROR_WINDOW_SECONDS` | `60` | 错误计数滑动窗口 |
| `MAX_SLOTS` | `5` | 每账号窗口错误 + 在途的合计上限 |
| `MAX_DELAY_SECONDS` | `10` | 演示用核验延迟上限 |
| `SESSION_TTL_SECONDS` | `3600` | 会话有效期 |
| `PROCESS_NAME` | `login` | 标识进程，体现在 `X-Served-By` |
