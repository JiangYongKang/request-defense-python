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

### 1.2 部分可信、多级转发链（逐跳信任校验）

接入拓扑可以是任意层数：服务前面有几层自己可控的代理，更前面还可能挂着
合作方/第三方网关，**并不是每一跳都可信**。判定从服务侧（XFF 的右/尾端）
开始，**从右向左逐跳校验**，而不是无条件信任固定数量的跳：

```
请求方/第三方网关 → 合作方代理(?) → 自有代理1 → 自有代理2 →(peer) 本服务
XFF 左端(可被请求方自填) ........ 右数第N跳 .... 右数第2跳   右数第1跳
```

记 `H = DEFENSE_PROXY_HOP_COUNT`（声明的自有代理层数）：

1. **peer（TCP 对端）必须命中白名单**，否则任何转发头都不采信；
2. XFF **右数第 1..H−1 跳构成"声明的可信段"**，每一跳都必须命中
   `DEFENSE_TRUSTED_PROXIES` 白名单；
3. 右数第 H 跳是**候选客户端身份**（候选跳本身不要求在白名单）；
4. 可信段内**只要有一跳不可信，立即停止向左采信**——该跳由它右侧
   （服务侧方向）最近的可信代理依据真实 TCP 对端写入，请求方无法把它
   伪造成任意第三方地址，因此**回退到这个"边界地址"作为最终身份**，
   其左侧所有条目（包括看似在白名单内的伪造条目）一律作废；
5. 候选跳本身仍命中白名单 → 大概率**声明层数偏少**（真实代理更多）：
   采纳该跳（至少位于不可伪造的链路上，不会采到请求方自填地址），
   但记 `candidate_within_trust_boundary` 提示运维核对拓扑。

> **为什么边界地址不可伪造？** 代理写入 XFF 的永远是"与它建连的真实 TCP
> 对端"。合作方/攻击者可以在自己控制的请求里任意填写 XFF 左段，却无法让
> 我方可信代理替它写下一个受害者的地址。因此把身份钉在"第一个越界跳"上，
> 攻击者只能让自己（或其紧邻网关）被计数，不能嫁祸他人或拿到多个配额。

### 1.3 结论原因码（`resolution_reason`，稳定可程序化区分）

每条判定都带机器可区分的结论码（见结构化日志与 `ClientIdentity`）：

| `resolution_reason` | 含义 | 最终身份 |
|---|---|---|
| `non_ip_peer` | peer 不是 IP（测试客户端等） | peer 原值 |
| `direct_untrusted_peer` | peer 不在白名单 | peer |
| `fallback_peer_missing_headers` | 可信 peer 但没带任何转发头 | peer |
| `fallback_peer_insufficient_hops` | 可用跳数少于声明层数 | peer |
| `fallback_peer_malformed_trusted_segment` | 可信段内某跳非法/超长 | peer |
| **`trust_boundary_breach_at_untrusted_hop`** | **可信段内出现不可信跳：信任边界突破** | **首个越界跳地址（边界地址）** |
| `forwarded_trusted_candidate_underdeclared` | 候选跳仍可信，声明层数偏少 | 候选跳（留痕） |
| `forwarded_ok` | 逐跳校验全部通过 | 候选跳 |
| `fallback_peer_x_real_ip_multi_hop_unverified` | 多层下只给 X-Real-IP，无法逐跳佐证 | peer |
| `x_real_ip_ok` / `fallback_peer_malformed_x_real_ip` | 单层 X-Real-IP 正常/非法 | 候选 / peer |

突破点细节同时放在 `trust_boundary`：
`{"hop_index": 右数第几跳, "boundary_addr": 边界地址,
"boundary_match_right": 其右侧可信的是哪一跳}`；
`verified_trusted_hops` 给出可信段实际校验通过的跳数，便于判断层数是否配错。

### 1.4 层数配错时结论始终偏向安全

| 配置与真实拓扑 | 结果 |
|---|---|
| 配多了（声明 3 跳，实际只有 1~2 层自有代理） | 可信段内必然遇到不可信跳 → 边界突破，身份=真实直连来源；**绝不会像旧模型那样选到请求方自填的左段** |
| 配少了（声明 1 跳，实际 2 层自有代理） | 候选跳命中白名单 → 采纳并记 `candidate_within_trust_boundary`，粒度变粗但不伪造，可由告警发现 |
| 层数一致 | 正常采纳右数第 H 跳 |

### 1.5 XFF / X-Real-IP 何时有效（速查表）

| 场景 | 行为 |
|---|---|
| peer 不在白名单，携带 XFF/X-Real-IP | 忽略转发头，身份=peer，记 anomaly；`deny` 策略下直接 403 |
| peer 在白名单，有 XFF | 逐跳校验（见 1.2），按上表原因码给出结论 |
| peer 在白名单，只有 X-Real-IP，且声明多层 | 单值头无法构成链、无法逐跳佐证 → 回退 peer，记 `x_real_ip_unverified_multi_hop` |
| peer 在白名单，只有 X-Real-IP，单层（H=1） | 取 X-Real-IP（非法则回退 peer） |
| peer 在白名单，但无任何转发头 | 身份回退为 peer，记 `missing_forwarded_headers` |
| 选中跳不是合法 IP / 跳数不足 | 身份回退为 peer，分别记 `malformed_xff_entry` / `xff_insufficient_hops` |

> **为什么从右往左取？** 攻击者可以在请求里自填任意 XFF 左段，
> 但可信反向代理只会把真实来源**追加在右侧**。右侧链路经过逐跳校验后，
> 左侧伪造内容无法影响结果。

所有判定步骤写入日志的 `input.identity_trace`，可逐条复查为什么采用/忽略了
某个身份、链路上哪一跳越过了信任边界。

### 1.6 对异常/恶意输入的稳定性与资源上界

* 非 IP peer（如某些测试客户端的 `testclient`）：视为不可信，不抛异常。
* IPv4-mapped IPv6（`::ffff:1.2.3.4`）自动归一化为 IPv4 匹配白名单。
* 容忍 `1.2.3.4:port` 形式的 XFF 条目；方括号 IPv6 `[::1]` 可解析。
* 多个 XFF 头：按接收顺序拼成一条链并记 `multiple_xff_headers`。
* **资源硬上界**（安全常数，在 `identity.py` 与 `/__defense/status` 的
  `identity.limits` 中可见）：
  最多读取 8 个 XFF 头（`max_xff_headers`）、合并后最多解析 64 跳
  （`max_xff_tokens`，只保留最靠右的跳）、单头值参与解析不超过 8192
  字符（`max_header_chars`，只保留右尾部）、单条目不超过 256 字符
  （`max_token_chars`，超长记 `xff_entry_too_long` 并回退）。
  trace 中的原始头值统一裁剪到 512 字符。超长链、大量重复头、非法字符、
  NUL/乱码都有确定结论，耗时与内存有上界，不会打崩请求处理。

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
| `DEFENSE_TRUSTED_PROXIES` | 空 | 可信代理 IP/CIDR，逗号分隔，如 `10.0.0.1,10.1.0.0/16`；**多级拓扑下列出全部自有代理跳**（每一跳都要能被逐跳命中） |
| `DEFENSE_PROXY_HOP_COUNT` | `1` | 声明的自有代理层数（≥1）；与真实层数不一致时结论仍偏向安全（见 1.4），但应保持一致以便精确识别 |
| `DEFENSE_ON_FORWARDED_FROM_UNTRUSTED` | `ignore` | 不可信 peer 携带转发头：`ignore`（忽略+留痕）/ `deny`（403） |
| `DEFENSE_RULES_FILE` | 空 | 规则 JSON 路径 |
| `DEFENSE_MAX_CLIENTS` | `100000` | 令牌桶 LRU 硬上限 |
| `DEFENSE_CLIENT_IDLE_TTL` | `300` | 客户端空闲回收秒数 |
| `DEFENSE_SWEEP_INTERVAL` | `60` | 空闲扫描周期秒数 |

辅助端点：`GET /__defense/status` 返回限流配置、在线桶数、规则引擎状态，
以及当前生效的信任拓扑 `identity`（模型名、白名单、声明层数、不可信来源
策略、解析资源上界），便于本地与线上核查"当前到底按什么拓扑在判定"
（该端点本身也经过防护层）。

---

## 6. 本地验证方法

### 6.1 跑全部测试

```bash
uv sync
uv run pytest                 # 87 个用例；-s 可看到每个判定的输入/结论打印
```

测试覆盖：并发临界（线程池 64×1000、协程 500 并发，允许数严格等于 burst）、
伪造 XFF / 自填左段 / 跳数篡改、缺失与畸形转发头、
规则文件缺失/坏 JSON/结构错/部分坏规则、规则不耗令牌、拒绝原因可区分、
LRU 上限与 20 万身份 churn 下的内存有界，以及本次新增的多级链路场景：

* **中间跳不可信（信任边界突破）**：2~3 级链中合作方网关不可信，
  任意伪造左段都钉死在边界地址，`trust_boundary` 指出越界跳；
* **声明层数与真实层数不一致**：配多/配少矩阵（真实 1~3 层 × 声明 1~3 跳），
  任何错配都不会采纳请求方自填的 `6.6.6.6`；
* **可信/不可信段混合**：攻击者在左段塞入白名单地址，链校验不会"重新变可信"；
* **异常头部**：600 跳超长链、30 个重复 XFF 头、20 万字符单头、
  NUL/乱码/非法 IP，结论稳定且单次耗时 < 20ms；
* **同一身份并发计数一致性**：400/500 协程下同一真实客户端（含边界突破
  聚合到同一网关）允许数严格等于 burst，`active_clients` 恰为 1。

`-s` 输出中每个请求都会打印 `[判定输入]`（peer、client_id、原因码、
trust_boundary、trace）与 `[最终结论]`，可直接对照复现线上判定。

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

### 6.3 多级链路本地复现

```bash
# 声明两层自有代理：10.0.0.1（一级）与 10.0.0.2（二级，即直连 peer）
DEFENSE_TRUSTED_PROXIES='10.0.0.1,10.0.0.2' DEFENSE_PROXY_HOP_COUNT=2 \
  DEFENSE_BURST=2 uv run uvicorn main:app --port 8000

# 正常两级链：身份=198.51.100.7
curl -s -H 'X-Forwarded-For: 198.51.100.7, 10.0.0.1' http://10.0.0.2:8000/

# 中间跳是不可信合作方网关：身份必须钉在 203.0.113.1（边界地址），
# 最左伪造的 6.6.6.6 被忽略；日志中 resolution_reason=
# trust_boundary_breach_at_untrusted_hop，trust_boundary 指明越界位置
curl -s -H 'X-Forwarded-For: 6.6.6.6, 203.0.113.1, 10.0.0.1' \
  http://10.0.0.2:8000/

# 查看当前生效的信任拓扑
curl -s http://127.0.0.1:8000/__defense/status | python3 -m json.tool
```

> 注：上面用地址区分 peer 仅为示意；真实环境里 peer 由 TCP 连接决定，
> curl 本机测试时 peer 是 127.0.0.1，把它配进白名单即可复现单跳，
> 多跳行为建议直接以 `uv run pytest -s tests/test_identity_chain.py
> tests/test_middleware_chain.py` 的判定日志为准。

### 6.4 规则拦截复现

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
* **逐跳信任而非固定跳数盲信**：只有服务侧连续若干跳全部命中白名单，才采纳
  更靠前的地址；中间任一跳不可信即钉死在不可伪造的边界地址上，
  其左侧（含伪造的白名单地址）全部作废。层数配多配少，结论都偏向安全。
* **兼容范围**：未新增任何必填配置；未配白名单、单层代理（`H=1`）、
  X-Real-IP、ignore/deny 策略、规则与限流的优先级与响应约定全部保持不变；
  旧的结构化日志字段全部保留，仅新增 `resolution_reason` /
  `trust_boundary` / `verified_trusted_hops` 与状态端点的 `identity` 块。
  **唯一的语义收紧**：`H>=2` 时不再盲信右数第 H 跳——可信段内的中间跳
  必须在白名单中（这正是本次要修复的"中间跳不可信也被采信"缺口）。
* **规则整体失败只降级规则维度且显式可见**，避免"一条坏规则让整站不可用"
  或"静默关闭全部防护"两个极端；环境变量级错误则 fail-fast。
* **规则先于限流且不共享额度**：拦截不消耗正常用户的令牌。
* **单一全局锁 + 单调时钟的令牌桶**：临界区极小（仅内存算术），
  优先保证判定的严格一致与可解释性，而非锁分片带来的复杂度。
  多级链识别出的同一 `client_id`（含边界突破聚合）在并发下仍只有一个桶，
  不会因转发链形态拿到多个配额或漏计。
* **身份判定过度阻断而非放松**：转发信息任何异常都回退到不可伪造的来源
  （peer 或信任边界地址），宁可让可信代理/边界网关被聚合计数，
  也不采用可能被伪造的身份。
* **解析资源有硬上界**：头数、跳数、头长度、条目长度全部封顶且只保留服务侧
  尾部，判定耗时与内存不随恶意输入增长。
