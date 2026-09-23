# request-defense-python

为 FastAPI 服务提供一套**本地即可运行、判定可解释、行为可复现**的外部请求防护层：

1. **按客户端维度限流**——同时约束平均速率与瞬时突发（令牌桶）；
2. **可配置的请求拦截规则**——命中即拒，规则非法时有明确且可区分的失败策略；
3. **反向代理后的真实客户端识别**——只有可信来源的转发信息才影响身份。

防护层以一个 Starlette 中间件实现，**不改变任何正常请求的原有接口行为**：
被放行的请求业务响应体不变，仅附加 `X-RateLimit-*` / `X-Request-ID` 响应头。

---

## 1. 架构与判定顺序

```
请求进入
  │
  ├─ 1. 身份判定  defense/identity.py   （永不拒绝；异常回退到 TCP peer）
  │
  ├─ 2. 拦截规则  defense/rules.py + defense/engine.py
  │        命中 ──► 403 rule_blocked（不消耗任何限流令牌）
  │        求值异常 ──► 403 rule_internal_error
  │
  └─ 3. 限流      defense/ratelimit.py  （按解析出的 client_id）
           超限 ──► 429 rate_limited（带 Retry-After）
           通过 ──► 调用业务路由
```

**优先级：身份 → 规则 → 限流。** 被规则拦截的请求不消耗限流令牌，因此攻击流量
（例如大量命中规则的扫描请求）无法耗尽被攻击者或其他客户端的限流预算（有测试覆盖）。

模块职责：

| 文件 | 职责 |
| --- | --- |
| `defense/identity.py` | 客户端身份解析、可信链路校验、判定轨迹（trail） |
| `defense/ratelimit.py` | 线程安全的有界令牌桶（平均速率 + 突发） |
| `defense/rules.py` | 规则的严格编译期校验与请求期求值 |
| `defense/config.py` | JSON 配置加载与校验，区分各类加载失败 |
| `defense/engine.py` | 判定链编排 + 审计日志（持有全部可变状态） |
| `defense/middleware.py` | ASGI 适配：生成拒绝响应、附加响应头 |
| `defense/factory.py` | 装配、故障安全启动、热重载 |

---

## 2. 客户端身份与信任模型

### 2.1 基本事实

- 服务端在 L4 唯一无法被伪造的身份是**直连对端 IP**（TCP peer）。
- `X-Forwarded-For`（XFF）/ `X-Real-IP` 是明文请求头，任何直连客户端都可以伪造。

因此转发头**只有在逐跳证明整条代理链都属于配置的可信集合时**才影响身份。

### 2.2 判定规则

设 `forward_depth = N`（服务前方可信代理层数）：

1. **直连 peer 不在可信集合** → 忽略一切转发头，`client_id = peer`，
   来源标记 `forged-headers-ignored`（攻击者伪造 XFF 无法获得新桶/新身份）。
2. **peer 可信** → 取 XFF **从右数第 N 个**地址作为客户端；其右侧的 N-1 个跳
   必须全部在可信集合中。XFF 更左侧的条目由客户端提供，直接忽略（防左填充伪造）。
   来源标记 `forwarded`。
3. XFF 缺失但 `X-Real-IP` 合法且 peer 可信 → 采用 X-Real-IP，来源 `real-ip`。
4. 以下任一异常都**回退到 peer 身份**（fail-closed，绝不因畸形输入而放开）：
   - XFF 含非法 IP、空条目、条目超过 32 个 → `forwarded-invalid`；
   - 条目数少于 `forward_depth`（链路不完整）→ `forwarded-incomplete`；
   - 右侧跳中存在不可信地址 → `forwarded-chain-untrusted`。
5. peer 缺失/不可解析 → 回退到常量键 `unknown` / peer 原值，`trusted=false`。

关键点：伪造、篡改或缺失转发信息时，身份只会**回退到不可伪造的 peer**，
无法绕过限流与拦截。每次判定的完整推导都记录在 `IdentityResult.trail` 中，
并随审计日志打印（见第 6 节）。

> 部署前提：`trusted_proxies` 必须只包含你真正控制的代理网段；
> `forward_depth` 必须等于可信代理的实际层数。配错时最保守的结果是回退到 peer，
> 不会错误信任外部地址。

---

## 3. 限流：平均速率 + 瞬时突发

每个客户端独立拥有一个令牌桶：

- `burst`：桶容量，即**瞬时可接受的最大突发/并发请求数**；
- `rate_per_sec`：令牌补充速度，即**长期平均速率上限（请求/秒）**。

实现保证：

- **并发精确**：取令牌在单一 `threading.Lock` 内原子完成，不存在漏计、
  重复计数或计数漂移（`tests/test_ratelimit.py` 用 10 线程 × 20 请求验证
  burst=100 时恰有 100 个通过；HTTP 层并发测试同样精确）。
- **拒绝可区分且带重试提示**：429 响应体含
  `error="rate_limited"`、`reason="rate_limited"`，并带
  `Retry-After`（整数秒）与 `X-RateLimit-*` 头；消息中给出建议等待秒数。
- **内存有界**：
  - 空闲超过“整桶补满时间”的桶会被回收（无信息损失，回收后再请求等于新桶）；
  - 身份数达到 `max_clients` 上限时先回收空闲桶，仍满则按 **LRU 淘汰最久未使用**
    的桶。5 万个不同身份轮换的测试中表大小恒为 `max_clients`。
  - 可调用 `engine.cleanup_idle_clients()` 做周期性主动回收（可选）。

注意：限流是**按身份**而不是按全局；不同 client_id 互不影响。

---

## 4. 拦截规则

### 4.1 规则格式

规则是 JSON 列表（内联在主配置的 `rules`，或由 `rules_file` 指向独立文件）：

```json
[
  {
    "id": "block-admin",                 // 必填，非空，全局唯一
    "description": "可选备注",
    "reason_code": "admin_area",         // 可选，出现在拒绝体 reason 中，默认 rule:<id>
    "match": {"field": "path", "op": "prefix", "value": "/admin"}
  },
  {
    "id": "sqli",
    "all": [                             // all = 所有 matcher 同时命中（AND）
      {"field": "query", "name": "q", "op": "regex", "value": "(?i)union\\s+select"}
    ]
  }
]
```

- `field`：`method` / `path` / `header` / `query` / `body`
- `op`：`present` / `equals` / `iequals` / `prefix` / `suffix` /
  `contains` / `regex` / `in`（`in` 的值必须是非空字符串列表）
- `header` / `query` 需额外提供 `name`（header 名大小写不敏感；query 取首个值）
- `body` 只检查请求体前 8192 字节（utf-8、替换非法字节），正常载荷照常透传
- 一条规则必须恰好提供 `match`（单个 matcher）或 `all`（matcher 列表）之一

规则按配置顺序求值，命中即拒（短路）。拒绝响应：

```json
{
  "error": "rule_blocked",
  "reason": "admin_area",
  "message": "Request rejected by interception rule block-admin.",
  "request_id": "..."
}
```

并带 `X-Defense-Reason: rule:block-admin`。规则错误（单请求求值期抛异常）
则返回可区分的 `error="rule_internal_error"`，记 ERROR 日志，且为 fail-closed。

### 4.2 非法规则 / 加载失败的策略（明确、可区分、不静默）

所有可在加载期检查的内容（结构、类型、正则编译、重复 id）都会**编译期严格校验**，
失败抛出可区分的异常类型：

| 情形 | 异常 |
| --- | --- |
| 文件不存在 | `defense.config.ConfigFileNotFound`（继承 `RuleConfigError`） |
| 文件不可读 / JSON 损坏 | `defense.errors.RuleFileError` |
| 顶层结构或数值非法 | `defense.config.ConfigSyntaxError` |
| 规则语法/正则非法、id 重复 | `defense.errors.RuleSyntaxError` |

两个应用时机：

- **启动**（`add_defense_safely`，`main.py` 默认）：
  - 文件不存在 → 安全默认（限流开、规则空），INFO 日志；
  - 文件存在但非法 → **CRITICAL 告警 + 安全默认继续启动**：服务可用、限流仍生效，
    规则为空，原因保存在 `app.state.defense_config_error`，**不会静默关闭全部防护**；
  - 设置环境变量 `REQUEST_DEFENSE_STRICT=1` → 改为启动失败（退出码非 0）。
- **运行期热重载**（`defense.factory.reload_defense`）：候选配置先完整校验，
  失败时返回 `(False, "具体异常类型: 详情")` 并记 ERROR，**旧规则与旧限流器继续
  生效**；只有校验成功才原子切换，不存在“防护被悄悄关掉”的窗口。

---

## 5. 可配置项

主配置文件路径由环境变量 `REQUEST_DEFENSE_CONFIG` 指定，默认 `defense_config.json`。
完整示例见 `defense_config.example.json` 与 `rules.example.json`。

```json
{
  "rate_limit":     { "rate_per_sec": 2.0, "burst": 5 },
  "trusted_proxies": ["10.0.0.0/8", "127.0.0.1/32"],
  "forward_depth":  1,
  "max_clients":    10000,
  "status_codes":   { "blocked": 403, "rate_limited": 429 },
  "rules_file":     "rules.example.json",
  "rules":          [ /* 内联规则，见第 4 节 */ ]
}
```

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `rate_limit.rate_per_sec` | `5.0` | 每客户端平均速率（令牌/秒），须 > 0 |
| `rate_limit.burst` | `10` | 每客户端瞬时突发上限（桶容量），正整数 |
| `trusted_proxies` | `[]` | 可信代理 IP/CIDR 列表；为空表示只信 peer |
| `forward_depth` | `1` | 可信代理层数（正整数） |
| `max_clients` | `10000` | 客户端桶表上限（LRU + 空闲回收保证有界） |
| `status_codes.blocked` | `403` | 规则拦截/规则错误的 HTTP 状态码 |
| `status_codes.rate_limited` | `429` | 限流拒绝的 HTTP 状态码 |
| `rules` | `[]` | 内联规则 |
| `rules_file` | 无 | 外部规则 JSON 文件（与内联合并） |

其它环境变量：

- `REQUEST_DEFENSE_STRICT=1`：配置非法时启动失败而非故障安全降级；
- `DEFENSE_LOG_LEVEL=INFO`：日志级别。

---

## 6. 可解释性：审计日志

每个请求输出一行结构化 `defense_verdict` 日志，包含**判定输入**与**最终结论**：

```
INFO defense defense_verdict request_id=... peer=10.0.0.1 client_id=8.8.8.8 \
  id_source=forwarded identity_trusted=True method=GET path=/health \
  verdict=deny:rate_limited retry_after=0.462 remaining=0 \
  trail=peer=10.0.0.1|xff_present=True|...|resolved_client=8.8.8.8|verdict=identity:forwarded
```

`verdict` 取值：`allow` / `deny:rule_blocked` / `deny:rule_internal_error` /
`deny:rate_limited`。拒绝响应同时带 `X-Request-ID`，可与日志关联。

拒绝原因对照（机器可区分）：

| 响应 | error | reason | 关键响应头 |
| --- | --- | --- | --- |
| 403 | `rule_blocked` | 规则的 `reason_code` | `X-Defense-Reason: rule:<id>` |
| 403 | `rule_internal_error` | `rule_internal_error` | `X-Request-ID` |
| 429 | `rate_limited` | `rate_limited` | `Retry-After`、`X-RateLimit-*` |

---

## 7. 本地验证

依赖（仓库 venv 已含）：fastapi、uvicorn、httpx、pytest、pytest-asyncio。

### 7.1 运行全部单测

```bash
python -m pytest -q
```

pytest 已配置 `log_cli=true`，测试运行时会实时打印每次判定的输入与结论。
覆盖场景包括：

- 并发临界请求（线程层与 HTTP 层，验证通过数严格等于 burst、不重不漏）；
- 伪造 XFF / X-Real-IP、可信链路、层数不匹配、畸形头、左填充伪造；
- 非法规则配置（正则、结构、重复 id、非法 op）、配置缺失/损坏/非法值；
- 热重载失败保留旧规则集；启动期故障安全降级与严格模式；
- 规则优先于限流（拦截请求不消耗令牌）；
- 5 万身份轮换下内存有界。

### 7.2 真实服务端复现

```bash
./demo.sh                 # 使用 defense_config.example.json
# 或
REQUEST_DEFENSE_CONFIG=defense_config.example.json \
  python -m uvicorn main:app --port 8077
```

脚本依次演示：正常请求行为不变 → 规则拦截（可区分原因）→ 突发边界后 429 →
可信代理 + 合法/畸形 XFF 的身份处理，并打印服务端判定轨迹。

模拟可信代理转发：

```bash
curl -H "X-Forwarded-For: 8.8.8.8" http://127.0.0.1:8077/health
```

> 说明：loopback 上 curl 可把源地址绑定为任意本地 IP，因此“不可信直连客户端
> 伪造 XFF”的场景以单元测试为准（生产环境中可信代理是独立主机，外部无法冒充）。
