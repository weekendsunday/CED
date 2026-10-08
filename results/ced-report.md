# 产品耦合误差报告

- 领域：`http1-framing`
- 拓扑：domain=http1-framing impls=9 chain=ref-cl-first → ref-te-first
- 用例数：64　实现对：8
- 耦合误差：28　其中安全级：26

## 分级统计

| 级别 | 数量 |
|---|---|
| security | 26 |
| unknown | 2 |

| 分歧类型 | 数量 |
|---|---|
| framing_boundary | 27 |
| framing_interpretation | 1 |

## 攻击场景升级（端到端 PoC）

> 只对 `security` 级发现升级。`unknown` / `compatibility` 一律不升级。

| 用例 | 场景 | 链路 | 量化 | 脚本 |
|---|---|---|---|---|
| `8b2611d2` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-lenient-cl | 被夹带字节数：forwarded=39、back_consumed=0、smuggled=39 | `results/pocs/poc_8b2611d2.py` |
| `d1df52a0` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-lenient-cl | 被夹带字节数：forwarded=39、back_consumed=0、smuggled=39 | `results/pocs/poc_d1df52a0.py` |
| `44f044fe` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-lenient-cl | 被夹带字节数：forwarded=44、back_consumed=0、smuggled=44 | `results/pocs/poc_44f044fe.py` |
| `3d0a4b5b` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-lenient-cl | 被夹带字节数：forwarded=39、back_consumed=0、smuggled=39 | `results/pocs/poc_3d0a4b5b.py` |
| `4d4c1c3b` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-lenient-cl | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_4d4c1c3b.py` |
| `de0a72c9` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-lenient-cl | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_de0a72c9.py` |
| `1cfdd820` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-lenient-cl | 被夹带字节数：forwarded=39、back_consumed=0、smuggled=39 | `results/pocs/poc_1cfdd820.py` |
| `984d5316` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-lenient-cl | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_984d5316.py` |
| `41d4a9a7` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-headers | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_41d4a9a7.py` |
| `ff9e2e44` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-headers | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_ff9e2e44.py` |
| `2eedc234` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-headers | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_2eedc234.py` |
| `823440d4` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-headers | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_823440d4.py` |
| `22fec6a0` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-headers | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_22fec6a0.py` |
| `58eb1c9e` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-headers | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_58eb1c9e.py` |
| `9134b348` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-headers | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_9134b348.py` |
| `62ba123b` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-request-line | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_62ba123b.py` |
| `70162be0` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-request-line | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_70162be0.py` |
| `b8f75cf9` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-request-line | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_b8f75cf9.py` |
| `276c3a0e` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-request-line | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_276c3a0e.py` |
| `fc4c74fb` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-request-line | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_fc4c74fb.py` |
| `63b954dd` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-request-line | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_63b954dd.py` |
| `c8f519aa` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-request-line | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_c8f519aa.py` |
| `c6b4341c` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-request-line | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_c6b4341c.py` |
| `2204c027` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-request-line | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_2204c027.py` |
| `f2b69e5e` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-request-line | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_f2b69e5e.py` |
| `7e6ac820` | 请求走私（HTTP/1.1 消息边界分歧） | ref-cl-first → ref-loose-request-line | 被夹带字节数：forwarded=0、back_consumed=0、smuggled=0 | `results/pocs/poc_7e6ac820.py` |

## 同类归并

> 判据：**同一对实现 + 同一分歧类型 = 同一类事实**，只留一条代表。
> 28 条发现归并后是 **4 类**（冗余 **7.0×**）。完整清单仍在 JSON 与结果库里。

| 级别 | 链路 | 类型 | 条数 | 代表 |
|---|---|---|---|---|
| security | ref-cl-first ↔ ref-loose-request-line | `framing_boundary` | 12 | `2204c027` |
| security | ref-cl-first ↔ ref-lenient-cl | `framing_boundary` | 8 | `3d0a4b5b` |
| security | ref-cl-first ↔ ref-loose-headers | `framing_boundary` | 7 | `9134b348` |
| security | ref-cl-first ↔ ref-lenient-cl | `framing_interpretation` | 1 | `984d5316` |

## 误差明细（每类一条代表）

### [security] `2204c027` — framing_boundary　（同类共 12 条）

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 同类其它样本：`62ba123b`、`70162be0`、`c6b4341c`、`b8f75cf9`、`276c3a0e`…等 11 条
- 判定理由：结构字段分歧（['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed']），且消融实验证明它由攻击者可直接发送的字节承载 → 具备可升级为安全影响的结构性前提；具体后果与 CWE 见领域映射（CWE-444）
- 可控性证据：把请求行规范化成 `POST / HTTP/1.1` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `0` | `96` |

- 最小复现样本（96 → 41 字节）：

  ```
  b'post / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc'
  ```

- 链路量化：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

**攻击场景**：请求走私（HTTP/1.1 消息边界分歧）（`desync`，CWE CWE-444）

前置与后端对『这条请求到哪里结束』判断不同：前置转发的字节里，后端只消费了一部分，剩下的成为后端眼中**下一条请求**的开头。于是攻击者可以在前置完全看不见的情况下，向后端注入一条自选请求 —— 前置的鉴权、限流、审计对这条被夹带的请求全部失效。

复现步骤：

1. 确认链路方向：客户端 → ref-cl-first（前置） → ref-loose-request-line（后端）
2. 把下面的最小复现样本原样发给 ref-cl-first：它包含一处非规范的定帧写法
3. ref-cl-first 按自身策略认为该请求占用 0 字节，全部转发给 ref-loose-request-line
4. ref-loose-request-line 按自身策略只消费 0 字节 → 剩余 **0 字节**留在后端缓冲区
5. 紧随其后的下一条请求会被拼接在那 0 字节之后，被夹带的字节成为后端眼中另一条请求的开头
6. 修复：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

- **被夹带字节数**：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面
- 可执行 PoC：`results/pocs/poc_2204c027.py`（离线算账；加 `--send HOST:PORT --i-am-authorized` 可真发）

### [security] `3d0a4b5b` — framing_boundary　（同类共 8 条）

- 对照：**ref-cl-first** ↔ **ref-lenient-cl**（轴：`cl_value`）
- 同类其它样本：`8b2611d2`、`d1df52a0`、`1cfdd820`、`44f044fe`、`4d4c1c3b`…等 7 条
- 判定理由：结构字段分歧（['framing_source', 'cl', 'body_len', 'consumed', 'leftover_len']），且消融实验证明它由攻击者可直接发送的字节承载 → 具备可升级为安全影响的结构性前提；具体后果与 CWE 见领域映射（CWE-444）
- 可控性证据：移除请求头 `CONTENT-LENGTH: +3` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
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
  b'POST / HTTP/1.1\r\nCONTENT-LENGTH: +3\r\n\r\nabc'
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
- 可执行 PoC：`results/pocs/poc_3d0a4b5b.py`（离线算账；加 `--send HOST:PORT --i-am-authorized` 可真发）

### [security] `9134b348` — framing_boundary　（同类共 7 条）

- 对照：**ref-cl-first** ↔ **ref-loose-headers**（轴：`header_space_before_colon`）
- 同类其它样本：`22fec6a0`、`41d4a9a7`、`2eedc234`、`ff9e2e44`、`823440d4`…等 6 条
- 判定理由：结构字段分歧（['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed']），且消融实验证明它由攻击者可直接发送的字节承载 → 具备可升级为安全影响的结构性前提；具体后果与 CWE 见领域映射（CWE-444）
- 可控性证据：移除请求头 `Content-Length : 5` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-headers |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'cl'` |
| `cl` | `None` | `5` |
| `body_len` | `0` | `5` |
| `consumed` | `0` | `63` |

- 最小复现样本（63 → 44 字节）：

  ```
  b'POST / HTTP/1.1\r\nContent-Length : 5\r\n\r\nhello'
  ```

- 链路量化：若 **ref-cl-first → ref-loose-headers** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

**攻击场景**：请求走私（HTTP/1.1 消息边界分歧）（`desync`，CWE CWE-444）

前置与后端对『这条请求到哪里结束』判断不同：前置转发的字节里，后端只消费了一部分，剩下的成为后端眼中**下一条请求**的开头。于是攻击者可以在前置完全看不见的情况下，向后端注入一条自选请求 —— 前置的鉴权、限流、审计对这条被夹带的请求全部失效。

复现步骤：

1. 确认链路方向：客户端 → ref-cl-first（前置） → ref-loose-headers（后端）
2. 把下面的最小复现样本原样发给 ref-cl-first：它包含一处非规范的定帧写法
3. ref-cl-first 按自身策略认为该请求占用 0 字节，全部转发给 ref-loose-headers
4. ref-loose-headers 按自身策略只消费 0 字节 → 剩余 **0 字节**留在后端缓冲区
5. 紧随其后的下一条请求会被拼接在那 0 字节之后，被夹带的字节成为后端眼中另一条请求的开头
6. 修复：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

- **被夹带字节数**：若 **ref-cl-first → ref-loose-headers** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面
- 可执行 PoC：`results/pocs/poc_9134b348.py`（离线算账；加 `--send HOST:PORT --i-am-authorized` 可真发）

### [security] `984d5316` — framing_interpretation

- 对照：**ref-cl-first** ↔ **ref-lenient-cl**（轴：`cl_duplicate_headers`）
- 判定理由：结构字段分歧（['status', 'framing_source', 'cl']），且消融实验证明它由攻击者可直接发送的字节承载 → 具备可升级为安全影响的结构性前提；具体后果与 CWE 见领域映射（CWE-444）
- 可控性证据：移除请求头 `Content-Length: 6`；移除请求头 `Content-Length: 5` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：定帧来源或请求体长度解释不同 → 边界可能错位（是否可升级取决于字节能否被夹带）
- CWE：CWE-444　场景：**desync**
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
- 可执行 PoC：`results/pocs/poc_984d5316.py`（离线算账；加 `--send HOST:PORT --i-am-authorized` 可真发）

---

> `security` 级 = 消息边界分歧 ∧ 分歧点由攻击者可控请求头承载。
> 未通过可控性消融的分歧一律标为 `unknown`，不作结论。