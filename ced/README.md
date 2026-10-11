# CED — 产品耦合误差检测

> 客户把产品交给我们，我们找出它们在**串联处的耦合误差**：
> 两个产品对同一份数据的理解不一致，且分歧点由攻击者可控的字节承载。

**核心公式**

$$\text{漏洞} \iff \text{语义分歧} \;\wedge\; \text{分歧点攻击者可控} \;\wedge\; \text{存在安全后果}$$

其中"由攻击者可直接发送的字节承载"不靠规则猜，而是**消融实验**机械地定位承载者：
逐条移除请求头重放两侧，若分歧消失，则该头就是这个分歧的承载者 —— 而请求头是攻击者能直接发的。
消融定位的是承载者，不等于证明可实际利用；`security` 的含义是「结构性前提成立」。

---

## 快速开始

只依赖 Python 3.11 标准库；**不需要 Docker，不需要网络**。

```bash
python -m ced impls                     # 看参照实现与定向对照
python -m ced regression                # 已知案例反验证（改判定后必跑）
python -m ced scan --mode axis --out report.md --json report.json --db ced.db
python -m ced scan --mode cross --limit 120 --out cross.md
python -m ced serve --policy ref-cl-first --data-port 8800 --api-port 8801
```

跑测试：

```bash
python ced/tests/test_pipeline.py        # 引擎与判定（16 项）
python ced/tests/test_socket_probe.py    # 探针协议一致性（2 项）
python ced/tests/test_chain_e2e.py       # 前置→探针 端到端（5 项，自带替身前置）
```

---

## 三种接入方式（runner）

| runner | 观测的是什么 | 用途 |
|---|---|---|
| `local` | 进程内参照实现的解析结果 | 内部基准、可复现的归因 |
| `socket` | 直连探针收到的字节 | 把任意位置的字节流变成观测 |
| **`chain`** | **真实前置转发出去的字节** | 观测客户产品对请求做了什么改写 |

`chain` 需要在前置**后面**放一个探针，并把探针控制口地址写进拓扑的 `probe_api`。
见 `topologies/example.yaml`。

### 探针协议

```
数据口：客户端发原始字节 → 半关闭写端 → 探针读到 EOF 立刻解析 → 以 HTTP 响应体返回观测 JSON
控制口：GET /health、GET /views、POST /reset
```

**刻意不使用"等空闲超时"**：客户端发完即半关闭，服务端立刻处理 ——
不存在「等待窗口 vs 空闲超时」的竞态（同类实现最常见的假阳性来源）。

---

## 模块划分（每个大功能一个模块）

| 模块 | 文件 | 职责 |
|---|---|---|
| 契约 | `contracts.py` | `ImplSpec` / `Observation` / `Divergence` / `Verdict` / `Finding` |
| 分帧内核 | `impls/http_reader.py` | 可配置的 HTTP/1.1 分帧解析器（**全平台唯一解析真源**） |
| 参照实现 | `impls/reference.py` | 9 个"只在一个策略点上不同"的实现 |
| 消息工具 | `httpmsg.py` | 请求的结构化拆解/重组（保留原始行尾） |
| 领域适配器 | `adapters/` | 协议 + HTTP/1.1 分帧（6 条分歧轴、分歧分类） |
| 变异 | `mutate/axes.py` `mutate/engine.py` | 6 条轴语料 + 确定性定向变异 |
| 探针 | `probe/evaluator.py` | local / socket / chain 三种观测源的分派 |
| | `probe/server.py` | 探针服务：数据口 + 控制口 |
| | `probe/chain.py` | 真实前置 → 探针的链路观测 |
| | `probe/errors.py` | `ProbeUnreachable` —— **探测失败必须抛错，不许合成观测** |
| 差分 | `differ/comparator.py` | 引擎的 oracle：只比较结构字段 |
| 判定 | `classify/upgradability.py` | 分歧 → security / compat / unknown，**含消融实验** |
| 最小化 | `minimize/ddmin.py` | ddmin + 语义保持 |
| 编排 | `orchestrate/` | 拓扑、链式复现模型 |
| 主流程 | `pipeline.py` | 计划 → 差分 → 判定 → 最小化 → 链式复现 |
| 反验证 | `regression.py` | 已知案例库回归（平台有效性自证） |
| | `cases/known/*.json` | 8 个已知分歧类别，期望值独立于工具输出 |
| 报告 | `report/renderer.py` | Markdown / JSON |
| 落库 | `store.py` | SQLite（自动创建父目录） |
| CLI | `cli.py` `__main__.py` | `scan` / `regression` / `serve` / `impls` |

### 数据流

```
axes(6 条轴语料) → Mutator(定向变异)
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
   实现 A 的观测                    实现 B 的观测
   local / socket / chain          local / socket / chain
        └───────────────┬───────────────┘
                        ▼
              differ（只比结构字段）→ Divergence
                        ▼
        classify：消融实验 → security / unknown / compat
                        ▼
        minimize（ddmin，保持分歧）→ 最小复现样本
                        ▼
        chain（前置→后端，量化被夹带字节）
                        ▼
           report.md / report.json / ced.db
```

---

## 反验证：平台有效性自证

```bash
python -m ced regression
```

8 个已知分歧类别（CL.TE 冲突、冲突 CL、非标准 TE token、前导零 CL、
冒号前空格、obs-fold 折行、TE 大小写、分块裸 LF），每个都标注了
**RFC 出处**与**预期的分歧类型 / 结构字段** —— 期望值是独立手写的，
不是工具输出，因此参考价值不循环。

断言是**非空转**的：必须真的产出分歧、类型必须相符、必须命中预期字段、
对照的两个实现必须是不同策略。**先证明能重新挖出已知的，再谈能发现未知的。**

---

## 设计取舍（为什么这样做）

| 取舍 | 理由 |
|---|---|
| 只用标准库 | 交付/评审环境可能没有网络与 Docker |
| 判据是**消融实验**而非规则堆叠 | 规则会把"报错文案不同"升级成漏洞；消融给出可复算的证据 |
| `compare_keys` 只含结构字段 | 从源头杜绝"拿诊断差异当结论" |
| 探测失败一律抛错 | 合成观测必然与基线不同，会把失败整片变成假阳性结论 |
| 探针不用空闲超时 | 竞态是假阳性主要来源 |
| 零字节观测一律跳过 | 端口探活产生的噪声连接不可能对应非空请求 |
| 参照实现只偏离基线一个策略点 | 每个分歧都能归因到具体的分帧策略 |

---

## 与 diffmine 的关系（收敛记录）

本实现收敛了 diffmine 的**链路观测**与**已知案例反验证**两项设计，
并按审查结论修掉了它们的实现缺陷：

| 原缺陷 | 本实现的做法 |
|---|---|
| 前置不可达时合成视角 → 100% 假阳性 | `ChainEvaluator` 直接抛 `ProbeUnreachable`；`scan` / CLI 中止且不产出结论 |
| 反验证基线空转（没跑通也 PASS） | `regression.py` 的四条非空转断言 + `cases/known` 的独立期望值 |
| 视角按到达顺序配对，迟到视角会串台 | 每次观测前 `POST /reset`，并跳过零字节噪声观测 |
| 探针等 3s 空闲 vs 差分器等 3s → 竞态 | 客户端发完即半关闭，服务端读到 EOF 立即处理 |
| `connect()` 不建父目录 | `store.connect()` 自动创建父目录（有测试） |

这些行为都有测试守着，见 `tests/test_chain_e2e.py`。

---

## 不做什么（边界）

- **不扫域名、不做资产治理**：差分需要两个视角，一个域名给不了两个视角。
- **不要求客户交出源码**：全程黑盒，探针只观测字节。
- **不把诊断差异当漏洞**：`compare_keys` 只含结构字段，有测试守着。
- **不做未授权测试**：设计上只跑本地容器矩阵或已授权链路。

---

## 当前边界与后续

已实现：HTTP/1.1 分帧领域（6 条轴）、三种接入方式、消融判定、ddmin 最小化、
已知案例反验证、报告与落库。

尚未实现：第二个领域适配器（URL / 路径归一化）、真实 Docker 编排
（`chain` 已可用，只差把客户产品的 compose 文件写出来）。
