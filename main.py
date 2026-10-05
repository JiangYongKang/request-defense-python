"""FastAPI 服务入口：原有接口行为不变，仅在最外层增加防护中间件。"""
from fastapi import FastAPI, Request

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
        "on_forwarded_from_untrusted": mw.config.on_forwarded_from_untrusted,
        "identity": mw.resolver.status_dict(),
        "rule_engine": mw.rules.status_dict(),
    }


# 配置在启动时显式加载：环境变量非法会直接启动失败（可预期、可区分），
# 绝不静默使用一个关闭防护的默认配置。规则文件整体非法只让规则降级，
# 限流仍生效、服务仍可用（见 docs/）。
_config = DefenseConfig.from_env()
_defense = DefenseMiddleware(app, config=_config)
app = _defense  # type: ignore[assignment]  # ASGI 最外层即为防护层
