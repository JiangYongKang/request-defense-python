# 请求防护层设计与使用文档

本服务在不改变正常请求接口行为（`GET /` 原样返回 `{"Hello": "World"}`）的前提下，
在最外层增加了一道纯 ASGI 防护中间件 `request_defense.DefenseMiddleware`，
由三个互相独立的模块构成：

```
请求 -> [身份判定] -> [规则拦截] -> [限流] -> 业务应用
```

所有判定都有**结构化日志**（logger 名 `request_defense`，
`event=defense_decision`），每条记录包含完整的判定输入、各阶段结论与最终结论。

---

## 1. 客户端身份与信任模型

### 1.1 信任锚点：TCP 直连对端

身份判定永远从 ASGI `scope["client"]` 的直连 IP（peer）开始，
该地址来自 TCP 连接，**不能被请求头伪造**。

### 1.2 X-Forwarded-For / X-Real-IP 何时有效

只有当 peer 命中 `DEFENSE_TRUSTED_PROXIES` 白名单（IP 或 CIDR）时，
转发头才被允许影响身份：

| 场景 | 行为 |
|---|---|
| peer 不在白名单，携带 XFF/X-Real-IP | 忽略转发头，身份=peer，记 anomaly；`deny` 策略下直接 403 |
| peer 在白名单，有 XFF | 从 XFF **右侧**（可信代理写入端）取第 `DEFENSE_PROXY_HOP_COUNT` 跳 |
| peer 在白名单，只有 X-Real-IP | 取 X-Real-IP |
| peer 在白名单，但无任何转发头 | 身份回退为 peer，记 `missing_forwarded_headers` |
| 选中跳不是合法 IP / 跳数不足 | 身份回退为 peer，分别记 `malformed_xff_entry` / `xff_insufficient_hops` |

> **为什么从右往左取？** 攻击者可以在请求里自填任意 XFF 左段，
> 但可信反向代理只会把真实来源**追加在右侧**。因此右侧第 N 跳不受左侧伪造内容影响。
>
> **跳数配置要与代理层数严格一致**：服务前面有几层自己可控的代理，就设几跳
> （单层 Nginx 保持默认 1；两层代理设 2）。配大了会把攻击者自填的左段选进来。

所有判定步骤写入日志的 `input.identity_trace`，可逐条复查为什么采用/忽略了某身份。

### 1.3 对异常输入的稳定性

* 非 IP peer（如某些测试客户端的 `testclient`）：视为不可信，不抛异常。
* IPv4-mapped IPv6（`::ffff:1.2.3.4`）自动归一化为 IPv4 匹配白名单。
* 容忍 `1.2.3.4:port` 形式的 XFF 条目；方括号 IPv6 `[::1]` 可解析。
* 多个 XFF 头：按接收顺序拼成一条链并记 `multiple_xff_headers`。

---

## 2. 规则与限流的优先级

判定顺序固定为：

1. **身份判定**（若配置了 `deny` 策略，伪造转发头在此直接拒绝）
2. **规则拦截**（命中即拒绝，HTTP 状态码取规则配置，默认 403）
3. **限流**（按 `client_id` 令牌桶判定）

设计含义：

* 恶意请求在最前面被挡下，**命中规则的请求不会消耗限流令牌**
  （否则攻击者可通过持续命中规则来挤占正常客户端的突发额度）。
* 不同拒绝原因完全可区分，见下表。

### 2.1 拒绝响应约定

所有拒绝返回 JSON，且带 `X-Defense-Decision` 响应头：

| 情形 | HTTP 状态 | `error` 字段 | retryable | 其他字段 |
|---|---|---|---|---|
| 不可信来源携带转发头且策略为 deny | 403 | `forwarded_headers_from_untrusted_source` | false | — |
| 命中拦截规则 | 规则 `status_code`（400-499，默认403） | `rule_denied` | false | `rule_id`、`rule_reason`、`detail` |
| 触发限流 | 429 | `rate_limited` | true | `retry_after_seconds`、`hint`；响应头 `Retry-After`（秒，向上取整） |

放行响应：`X-Defense-Decision: allow`，业务响应体与状态完全不变。

---

## 3. 限流语义

每客户端一个**令牌桶**：

* 容量 `DEFENSE_BURST` = 瞬时允许的最大突发请求数；
* 以 `DEFENSE_RATE_PER_SECOND` 个令牌/秒持续补充 = 长期平均速率上限；
* 每个新客户端的桶初始为满（允许冷启动打满一个突发）；
* 被拒绝不取令牌，重试等待时间不会因连续拒绝而漂移；
* `retry_after_seconds = 缺口令牌数 / 补充速率`。

**并发正确性**："补充令牌→尝试扣费/拒绝"全程在同一把锁内完成，
无论 asyncio 并发还是线程池并发，允许数严格等于可用令牌数：
不漏计、不重复计数、不漂移（测试中 64 线程×1000 次、500 协程均验证了这一点）。

**资源有界**（两条独立保证）：

* LRU 硬上限 `DEFENSE_MAX_CLIENTS`：桶数任何时刻都不超过该值，
  超出立即淘汰最久未使用者，即便面对海量伪造身份也不会 OOM；
* 空闲回收 `DEFENSE_CLIENT_IDLE_TTL`：空闲超过 TTL 的桶在
  `DEFENSE_SWEEP_INTERVAL` 周期扫描时删除（最迟 TTL+sweep 内回收，
  硬上限期间始终生效）。

---

## 4. 拦截规则

### 4.1 文件格式（`DEFENSE_RULES_FILE` 指向的 JSON）

```json
{"version": 1, "rules": [
  {"id": "block-admin", "field": "path_prefix", "match": "prefix", "value": "/admin"}
]}
```

| 字段 | 取值 | 说明 |
|---|---|---|
| `id` | 非空字符串，文件内唯一 | 必填 |
| `field` | `method` / `path` / `path_prefix` / `header` / `query` / `ip` | 匹配维度 |
| `match` | `equals` / `prefix` / `regex` / `contains` / `cidr` | 匹配方式 |
| `value` | 字符串 | 比较值（`regex` 启动时编译，`cidr` 启动时解析） |
| `header_name` | 字符串 | `field=header` 时必填（大小写不敏感） |
| `status_code` | 400-499 整数 | 默认 403 |
| `reason` | 非空字符串 | 默认 `blocked_by_rule` |

field 与 match 的合法组合在校验时强制检查（例如 `method` 只支持 `equals`，
`ip+cidr` 的 value 必须是合法 CIDR）。多条规则按文件顺序匹配，**首个命中生效**。

### 4.2 加载失败处理策略（明确且可预期）

| 情形 | `rule_engine.status` | loaded | 行为 |
|---|---|---|---|
| 未配置 `DEFENSE_RULES_FILE` | `no_rules_configured` | null | 不加载规则；限流正常 |
| 文件不存在 | `rules_file_missing` | false | 不加载规则；限流正常，状态可查 |
| JSON 解析失败 | `rules_file_invalid_json` | false | 整份规则不生效；**服务不宕、限流仍在**；启动日志与状态端点显式报错 |
| 文件不可读 | `rules_file_unreadable` | false | 同上 |
| 顶层结构错（非对象/`rules` 非数组） | `rules_file_invalid_structure` | false | 同上 |
| 个别规则非法 | `loaded_with_invalid_rules` | true | **跳过坏规则并逐条登记原因，好规则照常生效**，绝不因一条坏规则关掉全部防护 |

> 说明：规则整体不可用时**仅限"规则拦截"维度**等价于空规则，
> 这是显式记录并持续暴露（启动 WARNING 日志 + `/__defense/status`）的降级状态，
> 不是静默关闭；限流与身份判定完全不受影响。
> 而**环境变量配置非法**（如 burst=0、非法 CIDR 白名单）采取 fail-fast，
> 服务直接启动失败并打印具体配置项，避免带着错误信任/限流配置运行。

---

## 5. 可配置项（均为环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `DEFENSE_RATE_LIMIT_ENABLED` | `true` | 限流总开关 |
| `DEFENSE_RATE_PER_SECOND` | `5.0` | 每客户端平均速率（令牌/秒，正数） |
| `DEFENSE_BURST` | `10` | 每客户端突发容量（≥1 整数） |
| `DEFENSE_TRUSTED_PROXIES` | 空 | 可信代理 IP/CIDR，逗号分隔，如 `10.0.0.1,10.1.0.0/16` |
| `DEFENSE_PROXY_HOP_COUNT` | `1` | 从 XFF 右侧取第几跳（≥1） |
| `DEFENSE_ON_FORWARDED_FROM_UNTRUSTED` | `ignore` | 不可信 peer 携带转发头：`ignore`（忽略+留痕）/ `deny`（403） |
| `DEFENSE_RULES_FILE` | 空 | 规则 JSON 路径 |
| `DEFENSE_MAX_CLIENTS` | `100000` | 令牌桶 LRU 硬上限 |
| `DEFENSE_CLIENT_IDLE_TTL` | `300` | 客户端空闲回收秒数 |
| `DEFENSE_SWEEP_INTERVAL` | `60` | 空闲扫描周期秒数 |

辅助端点：`GET /__defense/status` 返回限流配置、在线桶数、信任模型与规则引擎状态
（该端点本身也经过防护层）。

---

## 6. 本地验证方法

### 6.1 跑全部测试

```bash
uv sync
uv run pytest                 # 55 个用例；-s 可看到每个判定的输入/结论打印
```

测试覆盖：并发临界（线程池 64×1000、协程 500 并发，允许数严格等于 burst）、
伪造 XFF / 自填左段 / 跳数篡改、缺失与畸形转发头、
规则文件缺失/坏 JSON/结构错/部分坏规则、规则不耗令牌、拒绝原因可区分、
LRU 上限与 20 万身份 churn 下的内存有界。

### 6.2 本地起服务手动复现

```bash
# 限流：每客户端 2/s、突发 3
DEFENSE_RATE_PER_SECOND=2 DEFENSE_BURST=3 \
  uv run uvicorn main:app --port 8000

# 连续请求，第 4 次起返回 429 + Retry-After
for i in $(seq 1 5); do
  curl -s -o /dev/null -w "%{http_code} " http://127.0.0.1:8000/; done; echo

# 反向代理信任模型：把 127.0.0.1 配成可信代理
DEFENSE_TRUSTED_PROXIES=127.0.0.1 DEFENSE_BURST=1 \
  uv run uvicorn main:app --port 8000
# 正常代理转发：身份为 XFF 中的地址
curl -s -H 'X-Forwarded-For: 198.51.100.7' http://127.0.0.1:8000/
# 伪造不同左段无法逃避（右跳不变）
curl -s -H 'X-Forwarded-For: 9.9.9.9, 198.51.100.7' http://127.0.0.1:8000/
# 直连不可信来源携带 XFF：被忽略，仍按 127.0.0.1 计数并留 anomaly
```

### 6.3 规则拦截复现

```bash
DEFENSE_RULES_FILE=$PWD/config/rules.example.json \
  uv run uvicorn main:app --port 8000

curl -i http://127.0.0.1:8000/admin          # 403 rule_denied / block-admin-paths
curl -i -H 'User-Agent: sqlmap/1.7' http://127.0.0.1:8000/   # 403
curl -s http://127.0.0.1:8000/__defense/status | python3 -m json.tool
```

把规则文件改成非法 JSON 后重启：服务照常启动、`/` 可访问，
但启动日志与 `/__defense/status` 中 `rule_engine.status`
变为 `rules_file_invalid_json` 并带具体解析错误。

---

## 7. 设计取舍小结

* **默认不信任任何转发头**：未配白名单时 XFF 完全不影响身份，部署即安全。
* **规则整体失败只降级规则维度且显式可见**，避免"一条坏规则让整站不可用"
  或"静默关闭全部防护"两个极端；环境变量级错误则 fail-fast。
* **规则先于限流且不共享额度**：拦截不消耗正常用户的令牌。
* **单一全局锁 + 单调时钟的令牌桶**：临界区极小（仅内存算术），
  优先保证判定的严格一致与可解释性，而非锁分片带来的复杂度。
* **身份判定过度阻断而非放松**：转发信息任何异常都回退为 peer，
  宁可让可信代理自身被聚合计数，也不采用可能被伪造的身份。
