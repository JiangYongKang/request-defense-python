"""FastAPI 服务入口：原有接口行为不变，仅在最外层增加防护中间件。"""
from fastapi import FastAPI, Query, Request

from request_defense.config import DefenseConfig
from request_defense.middleware import DefenseMiddleware

app = FastAPI(title="request-defense-python")


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/__defense/status")
def defense_status(request: Request) -> dict:
    """防护层运行状态（规则加载情况等），便于本地与线上核查。"""
    mw: DefenseMiddleware = request.scope["defense_middleware"]
    return {
        "rate_limit_enabled": mw.config.rate_limit_enabled,
        "rate_per_second": mw.config.rate_per_second,
        "burst": mw.config.burst,
        "active_clients": (mw.limiter.active_clients()
                           if mw.limiter is not None else 0),
        "trusted_proxies": list(mw.config.trusted_proxies),
        "proxy_hop_count": mw.config.proxy_hop_count,
        "forward_trust_mode": mw.config.forward_trust_mode,
        "trust_topology": mw.resolver.topology_dict(),
        "decision_history_size": mw.config.decision_history_size,
        "decision_history_records": len(mw.history),
        "on_forwarded_from_untrusted": mw.config.on_forwarded_from_untrusted,
        "rule_engine": mw.rules.status_dict(),
    }


@app.get("/__defense/decisions")
def defense_decisions(request: Request, limit: int = Query(default=20, ge=1, le=200)) -> dict:
    """本地最近的防护判定记录（新的在前），用于复现"判定输入 -> 最终结论"。

    仅保留在进程内存中；由 DEFENSE_DECISION_HISTORY_SIZE 控制容量，
    为 0（默认）时不保留任何记录。
    """
    mw: DefenseMiddleware = request.scope["defense_middleware"]
    return {
        "enabled": mw.config.decision_history_size > 0,
        "capacity": mw.config.decision_history_size,
        "stored": len(mw.history),
        "records": mw.history.recent(limit),
    }


# 配置在启动时显式加载：环境变量非法会直接启动失败（可预期、可区分），
# 绝不静默使用一个关闭防护的默认配置。规则文件整体非法只让规则降级，
# 限流仍生效、服务仍可用（见 docs/）。
_config = DefenseConfig.from_env()
_defense = DefenseMiddleware(app, config=_config)
app = _defense  # type: ignore[assignment]  # ASGI 最外层即为防护层
