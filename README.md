# request-defense-python

FastAPI 服务的外层请求防护层：**客户端身份判定（反代信任模型）→ 规则拦截 → 限流**，
以纯 ASGI 中间件实现，不改变正常接口行为。

## 快速开始

```bash
uv sync
uv run pytest                     # 55 个测试（并发临界 / 伪造转发 / 非法规则等）
DEFENSE_BURST=3 DEFENSE_RATE_PER_SECOND=2 \
  uv run uvicorn main:app --port 8000
curl http://127.0.0.1:8000/__defense/status
```

## 目录

- `request_defense/config.py` — 环境变量配置（非法值启动即失败）
- `request_defense/identity.py` — 可信代理白名单 + XFF 跳数的身份判定（全程 trace）
- `request_defense/rules.py` — JSON 规则引擎（加载失败原因可区分、部分失败不连坐）
- `request_defense/ratelimit.py` — 线程安全令牌桶（严格并发计数 + LRU/TTL 有界回收）
- `request_defense/middleware.py` — ASGI 防护中间件与结构化判定日志
- `config/rules.example.json` — 规则示例
- `tests/` — 单元与端到端测试（`-s` 可查看判定输入/结论日志）
- `docs/request-defense.md` — 信任模型、优先级、配置项与本地复现的完整说明
