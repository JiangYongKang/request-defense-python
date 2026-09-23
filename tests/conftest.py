"""测试公共设施。

* ``call_asgi``：直接打 ASGI 应用，可自由指定 client(peer) 与原始请求头，
  这样才能精确模拟"反向代理直连 + XFF"与"攻击者直连 + 伪造 XFF"。
* ``DecisionLogCapture``：捕获判定日志，满足"单测日志打印判定输入与最终结论"。
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import anyio
import httpx
import pytest

from request_defense.middleware import logger as defense_logger


@dataclass
class ASGIResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes

    def json(self):
        return json.loads(self.body.decode("utf-8"))


async def call_asgi(app, method: str, url: str, *,
                    headers: list[tuple[str, str]] | None = None,
                    client: tuple[str, int] = ("203.0.113.9", 54000)) -> ASGIResponse:
    """通过 httpx 的 ASGITransport 发请求，并注入自定义 client(peer)。"""
    request_headers = [(k.lower().encode("latin1"), v.encode("latin1"))
                       for k, v in (headers or [])]
    status_code_holder: dict = {}
    response_headers: list[tuple[bytes, bytes]] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            status_code_holder["code"] = message["status"]
            response_headers.extend(message.get("headers") or [])
        elif message["type"] == "http.response.body":
            pass  # 测试接口均无响应体读取需求以外的处理

    # 手动构造 scope，确保 client 完全可控
    scheme, _, host, path = _split_url(url)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": scheme,
        "path": path,
        "raw_path": path.encode("latin1"),
        "query_string": b"",
        "headers": request_headers,
        "client": client,
        "server": (host, 80),
        "root_path": "",
    }

    captured_body = bytearray()

    async def send_capture(message: dict) -> None:
        if message["type"] == "http.response.start":
            status_code_holder["code"] = message["status"]
            response_headers.extend(message.get("headers") or [])
        elif message["type"] == "http.response.body":
            captured_body.extend(message.get("body", b""))

    await app(scope, receive, send_capture)
    return ASGIResponse(
        status_code=status_code_holder["code"],
        headers={k.decode("latin1").lower(): v.decode("latin1")
                 for k, v in response_headers},
        body=bytes(captured_body),
    )


def _split_url(url: str) -> tuple[str, str, str, str]:
    assert url.startswith("http://")
    rest = url[len("http://"):]
    host, _, path = rest.partition("/")
    return "http", "", host, "/" + path


class DecisionLogCapture(logging.Handler):
    """收集 request_defense 的判定日志并打印（caplog 之外的显式保障）。"""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.records: list[dict] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            payload = json.loads(record.getMessage())
        except (ValueError, TypeError):
            return
        if payload.get("event") != "defense_decision":
            return
        self.records.append(payload)
        # 单测日志中显式打印：判定输入 -> 最终结论
        print("\n[判定输入] " + json.dumps(payload["input"], ensure_ascii=False))
        rl = payload.get("rate_limit")
        if rl:
            print("[限流判定] " + json.dumps(rl, ensure_ascii=False))
        if payload.get("rule"):
            print("[规则判定] " + json.dumps(payload["rule"], ensure_ascii=False))
        print("[最终结论] " + json.dumps(
            {"decision": payload["decision"], **({"deny": payload["deny"]}
                                                 if "deny" in payload else {})},
            ensure_ascii=False))

    @property
    def last(self) -> dict:
        return self.records[-1]


@pytest.fixture
def decision_logs() -> DecisionLogCapture:
    handler = DecisionLogCapture()
    defense_logger.addHandler(handler)
    try:
        yield handler
    finally:
        defense_logger.removeHandler(handler)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
