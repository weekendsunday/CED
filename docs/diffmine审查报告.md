# diffmine 实现审查报告

> 审查对象：`diffmine.zip`（P1 骨架，语义差分驱动的耦合误差检测平台）
> 审查方式：**静态通读 + 实机运行 + 测试替身注入**（本机无 Docker，故构造替身前置代理验证核心链路）
> 审查日期：2026-10-01

---

## 一、结论

**分层与职责划分是合格的，双视角抽象是正确的；但核心链路（chain）存在两个致命缺陷，导致 P1 的验收项不可信、且至今未被任何一次真实运行验证过。**

一句话：**差分逻辑本身成立**（我用替身前置首次真跑通并复现了它），**但 `--known` 自证机制是空转的、无前置时会静默产出 100% 假阳性。**

| 维度 | 评价 |
|---|---|
| 架构分层 | 好 —— 适配器/变异/差分/判定/编排/存储/报告 边界清晰 |
| 关键抽象 | 好 —— "前置的定帧决策 = 它转发出去的字节" 是正确且必要的抽象 |
| 工程完成度 | 中 —— direct 模式可跑；chain 模式无前置保护、无配对、无最小化 |
| 可验证性 | **差** —— 自证基线空转；真实链路必须 Docker，当前无法验证 |
| 交付件规范 | 中差 —— 中文文件名乱码、含 `.pyc`、与 `.gitignore` 自相矛盾 |

---

## 二、我实际做了什么（证据链）

| 步骤 | 命令 | 结果 |
|---|---|---|
| 1. 装依赖 | `pip install PyYAML` | `requirements.txt` 只含 PyYAML，**开箱不能跑**（未预装） |
| 2. direct 冒烟 | `run_loop.py --mode direct --cases 80` | ✅ 跑通：80 用例 / 0 分歧 / 55 歧义输入 |
| 3. chain 无前置 | `run_loop.py --mode chain --cases 12` | ❌ **12/12 全部 security-candidate**（100% 假阳性） |
| 4. chain + 透明替身前置 | 本机代理（字节透传） | ✅ **0 分歧** —— 证明"差分的差分"无自噪声 |
| 5. chain + 改写 CL 替身前置 | 本机代理（归一化 `Content-Length`） | ✅ **9/12 检出**，其中 1 条正确降级为 `compat` |
| 6. chain + keep-alive 替身前置 | 立即回复客户端、上游保持打开 | ❌ **8/8 全部 security-candidate**（替身未改任何字节） |
| 7. 已知案例回归 | `run_loop.py --mode chain --known`（前置未启动） | ❌ **3/3 PASS** —— 空转绿灯 |

> 替身代理仅用于验证，**未修改被测项目任何一行代码**。

---

## 三、致命问题（P0，必须修）

### F1. 前置不可达时静默产出 100% 假阳性

**现象**：前置没启动，`--mode chain` 依然跑出 "12 用例 / 12 分歧 / 12 security-candidate"。连**完全正常的**请求都被判成漏洞：

```
[security-candidate] a35bb609 — boundary
  安全后果：请求边界解释分歧 → 请求走私（CL.TE / TE.CL / TE.TE）
  CWE：CWE-444
  视角A（链路）：front-reject　视角B（基线）：probe-backend/0.1
  判别样本：b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc'
  规范形差异：
    "request_count": [0, 1]
    "requests": ['len=0', 'len=1']
    "stream_errors": ['len=1', 'len=0']
```

**根因链**（三处叠加）：

1. `src/runner/harness.py::chain_views` —— `try: send_raw(front) except OSError: pass`
   **吞掉了「连接 8080 被拒」**，流程继续。
2. 随后合成视角 `{"impl": "front-reject", "requests": [], "errors": ["front-did-not-forward"]}`，
   它与基线**必然**不同。
3. `src/adapters/http1_framing.py::_CLASSIFY_RULES` 把 `request_count` / `errors` 归为 `boundary`；
   `src/diff/verdict.py` 把 `boundary` 直接升为 `security-candidate`。

**修复**：

```python
# harness.chain_views：前置不可达必须响亮失败，绝不合成视角参与差分
try:
    self.send_raw(self.topo.front, payload)
except OSError as exc:
    raise ProbeUnreachable(f"前置 {self.topo.front} 不可达：{exc}") from exc
```
并把 `front-reject` 从"分歧"里剔除，或单列为 `infra` 类（级别 `not-a-finding`）。

### F2. 反验证基线空转绿灯（自证机制失效）

**现象**：前置**完全没启动**的情况下：

```
== 已知案例回归：3 个 ==
  [PASS] cl-te-conflict -> boundary (期望 boundary)
  [PASS] dup-cl-conflict -> boundary (期望 boundary)
  [PASS] te-bad-token  -> boundary (期望 boundary)
== 回归结果：3/3 通过 ==
```

**根因**：`run_known_regression` 只断言 `div.kind == expect_kind`，而 `front-reject` 同样产出 `boundary`。

**后果**：README 与 `docs/文件导览.md` 都声称"改 `normalize.py` / `verdict.py` 后必须过 `--known` 回归，全部存活才算过"——**这条纪律目前零防护力**，改坏了照样绿灯。

**修复**：断言必须更强，至少同时满足：

- 链路视角 `impl != "front-reject"`；
- `request_count > 0`；
- 差异出现在**预期字段**上（在 YAML 里加 `expect_fields: ["requests[1].framing", ...]`），而不只是 kind 级别的宽松匹配。

### F3. 核心能力至今未被真实运行验证（P1 验收未闭环）

README 自己勾掉了这一条：

```
- [ ] ≥10 个误差、人工确认 ≥3 真实 —— 需 chain 模式（Docker）跑真实 nginx
```

也就是说：**平台的关键能力（差分检出）从未在项目自己的环境里跑通过一次**。本次审查我用替身前置第一次让它跑通，并证明逻辑成立（见 §二 第 4、5 步）——但这是**外部验证**，项目自身没有。

**修复**：把替身前置（`transparent` / `rewriting` 两档）固化成 `tests/` 下的自动化测试，无需 Docker 即可跑：

- `test_no_front_raises`：无前置必须报错，不得产出分歧；
- `test_transparent_front_zero_divergence`：透明前置 → 0 分歧（防自噪声）；
- `test_rewriting_front_detects`：改写 CL 前置 → 检出预期条数；
- `test_known_regression_not_vacuous`：无前置时 `--known` 必须 FAIL。

---

## 四、重要问题（P1）

### F4. 视角按到达顺序配对，不按请求身份

`Harness._new_views()` 取"第一条 `conn_id` 比上次大的视角"，且 `view_of` / `chain_views` 都用它。
**若某条链路视角迟到，会被下一条用例当成基线消费** —— 基线错位，结论随即失真。

证据：把替身前置改成"立即回复客户端、上游连接保持打开"（这是 keep-alive 上游的真实形态）后，8/8 假阳性、单次耗时 27s。

**修复**：注入可识别的关联标记（如唯一的 `X-Probe-Case` 头或连接序号），并把"发送→取视角"做成严格配对；消费过的视角立即出队作废。

### F5. 探针 3s 才落视角，与 harness 3s 等待窗口贴脸

`probe_server.py: IDLE_TIMEOUT = 3.0`，`harness.py: VIEW_WAIT = 3.0` —— 两个 3.0s 直接重叠。
设计意图是"客户端停发即认为发完"，但真实前置（keep-alive 上游）**就是不停发**，于是变成竞态，抖动即假阳性。

**修复**：探针应当在**解析出一个完整请求后立即落视角**（增量落库），而不是等连接空闲。

### F6. kind 判定过粗：任何 `errors` 差异都升级为 boundary

```python
(("framing", "cl_raw", "te_raw", "body_len", "request_count",
  "chunk_count", "precedence", "stream_errors", "errors"), "boundary")
```

子串匹配，且 `errors` 在列；而 `_COMPAT_ONLY_TOKENS` 只覆盖 `anomalies`。
**后果**：两个实现仅在报错细节上不同，也会被升为 `security-candidate`（F1 正是沿这条路升级的）。

**修复**：区分**结构字段**（`framing` / `body_len` / `consumed` / `precedence` / `cl` / `te`）与**诊断字段**（`errors` / `anomalies`）；后者最多到 `compat`。

### F7. `security-candidate` 到 `security` 之间没有桥

当前 **100% 的输出都是 `security-candidate`**，报告里没有任何一条能升级为确定性结论，对客户不可用。文档已诚实标注"可控性重放"与"ddmin 最小化"属于 P2 —— 但这两件事恰恰是评分表里"技术性 25%"的核心看点。

**建议**（成本低、收益高）：

- **消融实验做可控性判定**：移除/规范化可疑头后若分歧消失，即证明分歧由攻击者可控字节承载；
- **ddmin 最小化**：把判别样本压到最小，同时保持分歧存活。

---

## 五、次要问题（P2）

| # | 问题 | 位置 | 修复 |
|---|---|---|---|
| F8 | 不创建父目录 → `sqlite3.OperationalError: unable to open database file`（首次运行即撞上） | `src/store/db.py:connect` | `os.makedirs(parent, exist_ok=True)` |
| F9 | ZIP 内中文文件名按 GBK 存储且无 UTF-8 标志 → 解包后成 `╬─╝■╡╝└└.md`，而 README 链接的是 `docs/文件导览.md`，**打不开** | 打包 | 改 ASCII 文件名，或重新打包 |
| F10 | 提交件含 10 个 `__pycache__/*.pyc` 与 `diffmine.db` / `report.md`，而 `.gitignore` 又声明忽略它们——自相矛盾 | 打包 | 剔除 `.pyc`；产物要么不放，要么在 README 里说明是样例输出 |
| F11 | 错别字："非 chunked 终coding" | `src/diff/verdict.py` | 应为"编码" |
| F12 | direct 模式 55 条"歧义"里 **10 条（18%）** 来自 `op_trailing_garbage` 追加的"请求后垃圾"（被解析成第二个请求 → `no-header-terminator`），是变异器人为噪声，不是真实歧义 | `src/mutate/mutator.py` | 把该算子从"歧义普查"信号里剔除，或单独归类 |
| F13 | `scripts/add_impl.sh` 只生成带 `TODO` 的空骨架，且是 bash（Windows 无 bash）——"10 分钟接入新实现"这个卖点实机不可用 | `scripts/` | 改成 Python 脚本并真正生成可跑配置 |

---

## 六、做对的地方（应保留并放大）

1. **双视角抽象正确**：探针置于前置之后，"前置的定帧决策 = 它转发出去的字节"。这是整个方案能成立的关键，且我没有看到更好的替代设计。
2. **差分的差分**：透明前置下 0 分歧，被实际验证成立（§二 第 4 步）——自噪声为零，这是可信差分的必要条件。
3. **分级不是全盘升级**：改写场景下 9/12 检出，其中 1 条正确降级为 `compat`（§二 第 5 步），说明 `verdict` 的分级逻辑在真实场景下是有效的。
4. **归一化显式排除波动字段**（`ts` / `conn_id` / `raw_head`），并有"改这里必须过回归"的意识——意识正确（虽然回归本身失效，见 F2）。
5. **`docs/文件导览.md`**："8 个文件 = 最小闭环"写得极好，答辩时是加分项。
6. **已知案例库**的设计思路（PoC 即回归测试）是对的，只是断言太弱。

---

## 七、与赛题的差距（时间紧，先看这段）

> 出自《第九届浙江省大学生网络与信息安全竞赛·作品挑战赛比赛说明》

**时间**：网络初赛材料提交 **截至 2026-10-25 24:00**。今天 2026-10-01 → **仅剩 24 天**（此前按 15 天排的计划把缓冲吃掉了）。

**评分表 → 当前差距**：

| 维度 | 权重 | 当前状态 |
|---|---|---|
| 创新性 | 25% | 中——"组件之间"的定位有新意；但判定器仍是规则匹配，缺可控性/最小化 |
| 技术性 | 25% | **受 F3 拖累**——核心链路未被真实运行验证 |
| 完成程度 | 20% | **受 F1/F2/F3 拖累**——现场跑不起来 / 跑起来是假阳性 |
| 应用潜力 | 15% | 中——场景明确（组件耦合误差检测），但缺真实客户链路演示 |
| 材料规范性 | 15% | **受 F9/F10 拖累**——文件名乱码、含 `.pyc` |

**提交物清单（目前一件都没有）**：
作品报告 PDF（≤20M）· 展示 PPT（≤50M）· 演示视频 mp4 ≤5min（≤100M，**需展示完整功能**）· 源代码+可执行程序+部署说明（≤100M）· 原创性声明 PDF · 其他材料（≤50M）。

**合规提醒**：赛题第九条明确禁止"以竞赛为由实施未经授权的网络攻击"。作品报告中必须显式声明：仅在本机容器矩阵与已授权链路上运行，不触碰真实目标——这条是"安全性与合规性 15%"的评分项。

---

## 八、建议的修复顺序

| 优先级 | 事项 | 预估 |
|---|---|---|
| 1 | **F1 + F2**：前置不可达抛错；`--known` 断言加强（禁止 front-reject 参与） | 半天 |
| 2 | **F3**：替身前置固化为 4 个自动化测试，纳入无 Docker 自测 | 1 天 |
| 3 | **F9 + F10 + F11 + F8**：打包与卫生问题（低成本、直接换分） | 半天 |
| 4 | **F6**：结构字段 / 诊断字段分离，压掉假阳性升级路径 | 半天 |
| 5 | **F4 + F5**：视角配对与探针增量落库（决定 chain 在真实 nginx 上是否稳定） | 1–1.5 天 |
| 6 | **F7**：可控性消融判定 + ddmin 最小化（技术性得分核心） | 2–3 天 |
| 7 | 用 Docker 真跑一次 nginx 链路，产出 README 里那条未打勾的验收 | 1 天 |

前 3 项做完，作品才具备"可运行、可复现、可自证"的底线。

---

## 九、修复与收敛状态（2026-10-01 更新）

### 已在 diffmine 本体修复并验证

| 缺陷 | 修复方式 | 验证证据 |
|---|---|---|
| **F1** 前置不可达时合成视角 → 12/12 假阳性 | `harness.chain_views` 不再合成：不可达/未转发一律抛 `ProbeUnreachable`；`run_loop.py` 捕获后**中止且不产出任何结论** | 无前置跑 chain → 中止、0 分歧；透明替身前置 → **0 分歧**（无假阳性） |
| **F2** 反验证基线空转（3/3 PASS） | `run_known_regression` 加三条**非空转**约束：①链路视角必须真的来自探针；②必须命中预期结构字段；③类型必须相符 | 无前置跑 `--known` → **0/3 通过**（修复前是 3/3 通过） |

### 其余问题的处置：**通过收敛解决，不再在 diffmine 本体修**

两套实现已合并为一套，**以 `ced` 为引擎内核**，diffmine 的「链路观测」与「已知案例反验证」两项设计已移植进来。逐条处置如下：

| 原缺陷 | 在 ced 中的处置 |
|---|---|
| F3 链路端到端从未验证 | 新增 `tests/test_chain_e2e.py`：自带替身前置，**无 Docker 也能跑**，5 项全过 |
| F4 视角按到达顺序配对、迟到视角串台 | 每次观测前 `POST /reset`，并跳过零字节噪声观测 |
| F5 探针等 3s 空闲 vs 差分器等 3s 的竞态 | 客户端发完即半关闭，服务端读到 EOF 立即处理；另外现在**按 HTTP 消息边界判断收全**（有 CL、无 TE 到边界就处理），真实前置不对上游半关闭时也不必干等空闲超时；判不出来才回落超时，且不合成视角 |
| F6 分类过粗（任何 `errors` 差异都升级为 boundary） | 改为**精确字段名**匹配；并有 `test_no_security_without_structural_change` 守住 |
| F7 缺可控性与最小化 | 消融实验定"攻击者可控"（可复算证据）+ ddmin 语义保持最小化 |
| F8 `connect()` 不建父目录 | ced 的 `store.connect()` 自动建父目录，有测试 |
| F11 错别字、F12 变异噪声 | ced 文案与语料重建，并补了已知案例库 |

**未处理**：F9（ZIP 中文文件名编码）、F10（提交件含 `.pyc`）—— 属于打包卫生，在最终提交前处理。
**F13**（`add_impl.sh` 只是带 TODO 的空骨架）—— 由 ced 的拓扑 + 探针协议取代。

### 本次收敛新增的能力（原先两套都没有）

| 能力 | 说明 |
|---|---|
| **已知案例反验证** | 8 个已知分歧类别，期望值**独立手写**（来自 RFC / 公开研究，非工具输出），Docker-free，`python -m ced regression` |
| **链路观测（chain runner）** | 观测真实前置转发出去的字节；失败必须抛错 |
| **零字节观测过滤** | 端口探活等噪声连接不得被当作用例视角 |
| 探针控制口 | `GET /health` `/views`、`POST /reset`，数据口以 HTTP 响应体返回观测 JSON（前置与直连都能用同一端口） |

