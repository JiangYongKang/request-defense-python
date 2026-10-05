# request-defense-python

FastAPI 服务的外层请求防护层：**客户端身份判定（部分可信、多级转发链的逐跳
信任模型）→ 规则拦截 → 限流**，以纯 ASGI 中间件实现，不改变正常接口行为。

多级代理（自有代理 + 合作方/第三方网关混挂、层数不固定）下，从服务侧沿
X-Forwarded-For 从右向左逐跳校验：只有连续若干跳全部命中可信白名单才采信
更靠前的地址；中间任一跳不可信即钉死在请求方无法伪造的信任边界地址上，
左侧伪造内容全部作废。每条判定带稳定原因码、越界位置与完整 trace。

## 快速开始

```bash
uv sync
uv run pytest                     # 87 个测试（多级链边界突破 / 并发计数一致 / 伪造转发等）
DEFENSE_BURST=3 DEFENSE_RATE_PER_SECOND=2 \
  uv run uvicorn main:app --port 8000
curl http://127.0.0.1:8000/__defense/status
```

## 目录

- `request_defense/config.py` — 环境变量配置（非法值启动即失败）
- `request_defense/identity.py` — 逐跳信任链身份判定（边界突破回退 / 稳定原因码 / 解析资源有界 / 全程 trace）
- `request_defense/rules.py` — JSON 规则引擎（加载失败原因可区分、部分失败不连坐）
- `request_defense/ratelimit.py` — 线程安全令牌桶（严格并发计数 + LRU/TTL 有界回收）
- `request_defense/middleware.py` — ASGI 防护中间件与结构化判定日志
- `config/rules.example.json` — 规则示例
- `tests/` — 单元与端到端测试（`-s` 可查看判定输入/结论日志）
  - `test_identity_chain.py` / `test_middleware_chain.py` — 多级链路与并发计数专项
- `docs/request-defense.md` — 信任模型、优先级、配置项与本地复现的完整说明
