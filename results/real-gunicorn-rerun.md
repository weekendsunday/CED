# 产品耦合误差报告

- 领域：`http1-framing`
- 拓扑：domain=http1-framing impls=6 chain=nginx-gunicorn → ref-cl-first
- 用例数：13　实现对：14
- 前置拒绝、不可观测而跳过的用例：**126**（不合成观测；真实前置对畸形请求返回 4xx 属正常行为）
- 耦合误差：33　其中安全级：2

## 分级统计

| 级别 | 数量 |
|---|---|
| security | 2 |
| unknown | 31 |

| 分歧类型 | 数量 |
|---|---|
| framing_boundary | 32 |
| framing_interpretation | 1 |

## 攻击场景升级（端到端 PoC）

> 只对 `security` 级发现升级。`unknown` / `compatibility` 一律不升级。

| 用例 | 场景 | 链路 | 量化 | 脚本 |
|---|---|---|---|---|
| `8b2611d2` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-lenient-cl | 被夹带字节数：forwarded=39、back_consumed=0、smuggled=39 | `results/pocs/poc_8b2611d2.py` |
| `984d5316` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-lenient-cl | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_984d5316.py` |

## 同类归并

> 判据：**同一对实现 + 同一分歧类型 = 同一类事实**，只留一条代表。
> 33 条发现归并后是 **9 类**（冗余 **3.7×**）。完整清单仍在 JSON 与结果库里。

| 级别 | 链路 | 类型 | 条数 | 代表 |
|---|---|---|---|---|
| security | ref-cl-first ↔ ref-lenient-cl | `framing_boundary` | 2 | `8b2611d2` |
| security | ref-cl-first ↔ ref-lenient-cl | `framing_interpretation` | 1 | `984d5316` |
| unknown | nginx-gunicorn ↔ ref-cl-first | `framing_boundary` | 5 | `2b6551b6` |
| unknown | nginx-gunicorn ↔ ref-lenient-cl | `framing_boundary` | 5 | `2b6551b6` |
| unknown | nginx-gunicorn ↔ ref-te-first | `framing_boundary` | 5 | `2b6551b6` |
| unknown | gunicorn-backend ↔ ref-cl-first | `framing_boundary` | 4 | `5ff10947` |
| unknown | gunicorn-backend ↔ ref-lenient-cl | `framing_boundary` | 4 | `5ff10947` |
| unknown | gunicorn-backend ↔ ref-te-first | `framing_boundary` | 4 | `5ff10947` |
| unknown | nginx-gunicorn ↔ gunicorn-backend | `framing_boundary` | 3 | `5ff10947` |

## 误差明细（每类一条代表）

### [security] `8b2611d2` — framing_boundary　（同类共 2 条）

- 对照：**ref-cl-first** ↔ **ref-lenient-cl**（轴：`cl_value`）
- 同类其它样本：`c5cb884a`
- 判定理由：结构字段分歧（['framing_source', 'cl', 'body_len', 'consumed', 'leftover_len']），且消融实验定位到它由攻击者可直接发送的字节承载 → 具备可升级为安全影响的结构性前提（不等于已实机利用）；具体后果与 CWE 见领域映射（CWE-444）
- 消融证据：移除请求头 `Content-Length: 03` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE（候选，以实机复现为准）：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-lenient-cl |
|---|---|---|
| `framing_source` | `'none'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `56` | `59` |
| `leftover_len` | `3` | `0` |

- 最小复现样本（59 → 42 字节）：

  ```
  b'POST / HTTP/1.1\r\nContent-Length: 03\r\n\r\nabc'
  ```

- 链路量化：若 **ref-cl-first → ref-lenient-cl** 串联：前置转发 39 字节，后端只消费 0 字节 → **39 字节被夹带**，将成为下一条请求的开头

**攻击场景**：请求走私（HTTP/1.1 消息边界分歧）（`desync`，CWE CWE-444）

前置与后端对『这条请求到哪里结束』判断不同：前置转发的字节里，后端只消费了一部分，剩下的成为后端眼中**下一条请求**的开头。于是攻击者可以在前置完全看不见的情况下，向后端注入一条自选请求 —— 前置的鉴权、限流、审计对这条被夹带的请求全部失效。

复现步骤：

1. 确认链路方向：客户端 → ref-cl-first（前置） → ref-lenient-cl（后端）
2. 把下面的最小复现样本原样发给 ref-cl-first：它包含一处非规范的定帧写法
3. ref-cl-first 按自身策略认为该请求占用 39 字节，全部转发给 ref-lenient-cl
4. ref-lenient-cl 按自身策略只消费 0 字节 → 剩余 **39 字节**留在后端缓冲区
5. 紧随其后的下一条请求会被拼接在那 39 字节之后，被夹带的字节成为后端眼中另一条请求的开头
6. 修复：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

- **被夹带字节数**：若 **ref-cl-first → ref-lenient-cl** 串联：前置转发 39 字节，后端只消费 0 字节 → **39 字节被夹带**，将成为下一条请求的开头
- 可执行 PoC：`results/pocs/poc_8b2611d2.py`（离线算账；`--chain http://127.0.0.1:8801` 实机取证；`--send HOST:PORT --i-am-authorized` 可真发）

### [security] `984d5316` — framing_interpretation

- 对照：**ref-cl-first** ↔ **ref-lenient-cl**（轴：`cl_duplicate_headers`）
- 判定理由：结构字段分歧（['status', 'framing_source', 'cl']），且消融实验定位到它由攻击者可直接发送的字节承载 → 具备可升级为安全影响的结构性前提（不等于已实机利用）；具体后果与 CWE 见领域映射（CWE-444）
- 消融证据：移除请求头 `Content-Length: 6`；移除请求头 `Content-Length: 5` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：定帧来源或请求体长度解释不同 → 边界可能错位（是否可升级取决于字节能否被夹带）
- CWE（候选，以实机复现为准）：CWE-444　场景：**desync**
- 修复建议：统一 CL/TE 优先级与语法接受度；两侧对齐同一份定帧规范

| 观测字段 | ref-cl-first | ref-lenient-cl |
|---|---|---|
| `status` | `400` | `0` |
| `framing_source` | `'reject'` | `'cl'` |
| `cl` | `None` | `6` |

- 最小复现样本（71 → 62 字节）：

  ```
  b'POST / HTTP/1.1\r\nContent-Length: 6\r\nContent-Length: 5\r\n\r\nhello'
  ```

- 链路量化：若 **ref-cl-first → ref-lenient-cl** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

**攻击场景**：请求走私（HTTP/1.1 消息边界分歧）（`desync`，CWE CWE-444）

前置与后端对『这条请求到哪里结束』判断不同：前置转发的字节里，后端只消费了一部分，剩下的成为后端眼中**下一条请求**的开头。于是攻击者可以在前置完全看不见的情况下，向后端注入一条自选请求 —— 前置的鉴权、限流、审计对这条被夹带的请求全部失效。

复现步骤：

1. 确认链路方向：客户端 → ref-cl-first（前置） → ref-lenient-cl（后端）
2. 把下面的最小复现样本原样发给 ref-cl-first：它包含一处非规范的定帧写法
3. ref-cl-first 按自身策略认为该请求占用 0 字节，全部转发给 ref-lenient-cl
4. ref-lenient-cl 按自身策略只消费 0 字节 → 剩余 **0 字节**留在后端缓冲区
5. 紧随其后的下一条请求会被拼接在那 0 字节之后，被夹带的字节成为后端眼中另一条请求的开头
6. 修复：统一 CL/TE 优先级与语法接受度；两侧对齐同一份定帧规范

- **被夹带字节数**：若 **ref-cl-first → ref-lenient-cl** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面
- 可执行 PoC：`results/pocs/poc_984d5316.py`（离线算账；`--chain http://127.0.0.1:8801` 实机取证；`--send HOST:PORT --i-am-authorized` 可真发）

### [unknown] `2b6551b6` — framing_boundary　（同类共 5 条）

- 对照：**nginx-gunicorn** ↔ **ref-cl-first**（轴：`cross`）
- 同类其它样本：`5ff10947`、`a35bb609`、`8b2611d2`、`4f764b02`
- 判定理由：结构字段分歧（['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed']），但消融实验无法定位到单条可控承载者 → 需人工复核
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE（候选，以实机复现为准）：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | nginx-gunicorn | ref-cl-first |
|---|---|---|
| `accepted` | `True` | `False` |
| `status` | `200` | `400` |
| `framing_source` | `'cl'` | `'reject'` |
| `cl` | `3` | `None` |
| `body_len` | `3` | `0` |
| `consumed` | `262` | `0` |

- 原始样本：

  ```
  b'POST / HTTP/1.1\nHost: localhost\nContent-Length: 03\n\nabc'
  ```

### [unknown] `2b6551b6` — framing_boundary　（同类共 5 条）

- 对照：**nginx-gunicorn** ↔ **ref-lenient-cl**（轴：`cross`）
- 同类其它样本：`5ff10947`、`a35bb609`、`8b2611d2`、`4f764b02`
- 判定理由：结构字段分歧（['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed']），但消融实验无法定位到单条可控承载者 → 需人工复核
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE（候选，以实机复现为准）：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | nginx-gunicorn | ref-lenient-cl |
|---|---|---|
| `accepted` | `True` | `False` |
| `status` | `200` | `400` |
| `framing_source` | `'cl'` | `'reject'` |
| `cl` | `3` | `None` |
| `body_len` | `3` | `0` |
| `consumed` | `262` | `0` |

- 原始样本：

  ```
  b'POST / HTTP/1.1\nHost: localhost\nContent-Length: 03\n\nabc'
  ```

### [unknown] `2b6551b6` — framing_boundary　（同类共 5 条）

- 对照：**nginx-gunicorn** ↔ **ref-te-first**（轴：`cross`）
- 同类其它样本：`5ff10947`、`a35bb609`、`8b2611d2`、`4f764b02`
- 判定理由：结构字段分歧（['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed']），但消融实验无法定位到单条可控承载者 → 需人工复核
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE（候选，以实机复现为准）：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | nginx-gunicorn | ref-te-first |
|---|---|---|
| `accepted` | `True` | `False` |
| `status` | `200` | `400` |
| `framing_source` | `'cl'` | `'reject'` |
| `cl` | `3` | `None` |
| `body_len` | `3` | `0` |
| `consumed` | `262` | `0` |

- 原始样本：

  ```
  b'POST / HTTP/1.1\nHost: localhost\nContent-Length: 03\n\nabc'
  ```

### [unknown] `5ff10947` — framing_boundary　（同类共 4 条）

- 对照：**gunicorn-backend** ↔ **ref-cl-first**（轴：`cross`）
- 同类其它样本：`a35bb609`、`8b2611d2`、`91f504a5`
- 判定理由：结构字段分歧（['consumed']），但消融实验无法定位到单条可控承载者 → 需人工复核
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE（候选，以实机复现为准）：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | gunicorn-backend | ref-cl-first |
|---|---|---|
| `consumed` | `141` | `58` |

- 原始样本：

  ```
  b'POST / HTTP/1.1\r\nHost: localhost\r\nCONTENT-LENGTH: 3\r\n\r\nabc'
  ```

### [unknown] `5ff10947` — framing_boundary　（同类共 4 条）

- 对照：**gunicorn-backend** ↔ **ref-lenient-cl**（轴：`cross`）
- 同类其它样本：`a35bb609`、`8b2611d2`、`91f504a5`
- 判定理由：结构字段分歧（['consumed']），但消融实验无法定位到单条可控承载者 → 需人工复核
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE（候选，以实机复现为准）：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | gunicorn-backend | ref-lenient-cl |
|---|---|---|
| `consumed` | `141` | `58` |

- 原始样本：

  ```
  b'POST / HTTP/1.1\r\nHost: localhost\r\nCONTENT-LENGTH: 3\r\n\r\nabc'
  ```

### [unknown] `5ff10947` — framing_boundary　（同类共 4 条）

- 对照：**gunicorn-backend** ↔ **ref-te-first**（轴：`cross`）
- 同类其它样本：`a35bb609`、`8b2611d2`、`91f504a5`
- 判定理由：结构字段分歧（['consumed']），但消融实验无法定位到单条可控承载者 → 需人工复核
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE（候选，以实机复现为准）：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | gunicorn-backend | ref-te-first |
|---|---|---|
| `consumed` | `141` | `58` |

- 原始样本：

  ```
  b'POST / HTTP/1.1\r\nHost: localhost\r\nCONTENT-LENGTH: 3\r\n\r\nabc'
  ```

### [unknown] `5ff10947` — framing_boundary　（同类共 3 条）

- 对照：**nginx-gunicorn** ↔ **gunicorn-backend**（轴：`cross`）
- 同类其它样本：`a35bb609`、`8b2611d2`
- 判定理由：结构字段分歧（['consumed']），但消融实验无法定位到单条可控承载者 → 需人工复核
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE（候选，以实机复现为准）：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | nginx-gunicorn | gunicorn-backend |
|---|---|---|
| `consumed` | `262` | `141` |

- 原始样本：

  ```
  b'POST / HTTP/1.1\r\nHost: localhost\r\nCONTENT-LENGTH: 3\r\n\r\nabc'
  ```

---

> `security` 级 = 结构性分歧 ∧ 由攻击者可直接发送的字节承载（结构性前提成立，不等于已实机利用）。
> 消融实验未能定位承载者的分歧一律标为 `unknown`，不作结论。