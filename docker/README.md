# docker/ —— 真实链路演示栈（nginx 前置 → 探针扮演后端）

> **2026-10-02 更新**：本机已安装 Docker Desktop 4.93（`F:\docker`）并**实机跑通了这套栈**。
> 下面的核验清单逐条跑过，结论、实测到的前置定帧行为、以及本轮暴露并修掉的三个缺陷，
> 都记在「实机验证记录」一节里；仍剩三项未覆盖，也在那里列明。
> 逐字保留的纪律：本文件里凡是标着「实测」的输出都是在**本开发机**上真实跑出来的；
> 标着「期望」的都是按代码推断、**没有**跑过 Docker 部分。

---

## 这一栈是什么

真实产品不是参照实现：这个栈里跑的是**官方 nginx 镜像**（`nginx:1.25-alpine`）和一个**真的
gunicorn**。探针（`ced/probe/server.py`）扮演 nginx 后面的那个后端，它把「收到的字节」记成
一个视角，CED 引擎通过控制口把视角取回来，和本地参照实现做差分。

```mermaid
flowchart LR
    C["客户端<br/>原始 HTTP/1.1 字节"] -->|"宿主 8080 → 容器 80"| N["nginx:1.25-alpine<br/>前置 · 被观测对象"]
    N -->|"proxy_pass probe:8800"| P["CED 探针<br/>扮演真实后端"]
    P -->|"按 policy 定帧"| V[("视角 views<br/>id 单调递增")]
    A["CED 引擎<br/>runner=chain"] -->|"发原始字节（绕开探针）"| N
    A -->|"POST /reset 清空视角"| P
    A -->|"GET /views 取回视角"| P
    A -.->|"与本地参照实现差分"| R["ref-cl-first / ref-te-first / ref-lenient-cl"]
```

控制口在宿主 `127.0.0.1:8801`（`GET /health`、`GET /views`、`POST /reset`）；
数据口 `8800` **只在 compose 内部网络**，不映射到宿主 —— 它只该被 nginx / gunicorn 访问。

### 目录与端口

| 路径 | 作用 |
|---|---|
| `docker/docker-compose.yml` | 四个服务：`probe`、`front`（必需）+ `gateway`、`backend`（profile `gunicorn`，默认不启） |
| `docker/front/nginx.conf` | **被测的 nginx 配置**（第一档：nginx → 探针） |
| `docker/front/nginx-gateway.conf` | 第二档的入口 nginx（gateway → gunicorn） |
| `docker/probe/Dockerfile` | 探针镜像，只 COPY `ced/` 与 `main.py`，上下文是**仓库根** |
| `docker/backend/{app.py,Dockerfile}` | 真正的 gunicorn 后端（第二档） |
| `docker/up.ps1` / `down.ps1` / `snapshot.ps1` | 起栈并等 ready / 拆栈 / 离线快照与恢复 |
| `../.dockerignore` | 让构建上下文最小（排除 `refs/`、`results/`、`docs/`、`docker/images/` 等） |
| `ced/topologies/real-nginx-probe.yaml` | 第一档拓扑（nginx 8080 ↔ 探针 8801） |
| `ced/topologies/real-nginx-gunicorn.yaml` | 第二档拓扑（还要 `-Gunicorn` 起 gateway/backend） |

端口是**跨文件约定**，改一处必须同步改另一处：

| 宿主端口 | 指向 | 谁在用 |
|---|---|---|
| `8080` | nginx(front) 容器 80 | `real-*.yaml` 里 `customer-gateway.endpoint` |
| `8801` | 探针控制口 | `real-*.yaml` 里 `probe_api`（两个 chain 实现共用） |
| `8081` | nginx(gateway) 容器 8081 | gunicorn 拓扑里 `nginx-gunicorn.endpoint` |
| `8090` | gunicorn 容器 8090 | gunicorn 拓扑里 `gunicorn-backend.endpoint` |
| （无） | 探针数据口 8800 | 只在 compose 内部网络 |

---

## 快速开始（在**有 Docker** 的机器上）

```powershell
# 0) 前置：Docker Desktop 已启动；宿主 8080 / 8801 空闲
docker compose version

# 1) 起栈 —— 脚本会 up -d --build，然后轮询 http://127.0.0.1:8801/health 直到 ready
powershell -NoProfile -ExecutionPolicy Bypass -File docker/up.ps1

# 2) 跑扫描（**必须带 --limit**，理由见「常见问题」）
python -m ced scan --topology ced/topologies/real-nginx-probe.yaml --limit 12 --out results/real.md

# 3) 收工
powershell -NoProfile -ExecutionPolicy Bypass -File docker/down.ps1
```

`docker/up.ps1` 干三件事：`docker compose up -d --build` → 轮询探针 `/health`（默认 90 秒超时，
超时会把 `docker compose ps` 与 `logs probe` 打出来再退出）→ 从宿主 8080 发一条
`POST /ced-smoke` 穿过 nginx，把探针记录到的观测 JSON 原样打印。

### 期望输出

**期望**（下面每一段在本开发机上**都没有实机跑过**，是照代码推断的）：

```
[1/3] docker compose up -d --build
...
[2/3] 等探针控制口 ready（最多 90 秒）
     探针 ready -> {"status":"ok"}
[3/3] 冒烟：POST /ced-smoke 经 nginx 转发，看探针记录了哪些字段
HTTP/1.1 200 OK                              ← 这是 nginx 回给客户端的响应
...
{"id":1,"raw_len":58,"ok":true,"error":null,  ← 这是探针记下的"它收到了什么"
 "fields":{"accepted":true,"status":200,"framing_source":"cl",
           "cl":5,"te":[],"body_len":5,"consumed":58,"leftover_len":0}}
     ↑ 字段名与结构取自本机实测的探针响应；这里的数值是示意（实跑时 raw_len/consumed
       取决于 nginx 实际转发出去多少字节 —— 那正是要观测的东西）

栈已就绪。下一步：
  python -m ced scan --topology ced/topologies/real-nginx-probe.yaml --limit 12 --out results/real.md
```

扫描命令**期望**打印成这样（格式逐字取自 `ced/cli.py::_cmd_scan` 的 `print`；数字取决于
`--limit` 与语料）：

```
--------------------------------------------------------------
[结果] 用例 12 | 实现对 5 | 耦合误差 <D> | 安全级 <S>
  [!!] <case_id>  customer-gateway ↔ ref-lenient-cl  framing_boundary  最小化 59→42B
[产物] results/real.md
[产物] results/pocs  （<K> 个端到端 PoC 脚本）
        results\pocs\poc_<case_id>.py
```

- `用例 N` = 进池的语料条数（`--limit` 裁剪后的手写语料；`--llm` 的提案不受 limit 限制）
- `实现对 J` = 本次跑的**对照对数**（axis 模式：按分歧轴的定向对照 + 客户实现与各参照的交叉对照）
- `耦合误差 D` / `安全级 S` = 结构字段有分歧的条数 / 其中判为安全级（CWE-444 等）的条数
- 每条安全级发现会生成一份端到端 PoC 脚本到 `--poc-dir`

### 无 Docker 时的实测输出（用 TCP 直通中继顶替 nginx）

在没有 Docker 的机器上，用 TCP 直通中继也能把「探针 + 前置 + chain runner + CLI」这条**管道**用
一个逐字节转发的 TCP 中继（顶替 nginx 的位置，监听 8180 → 探针 8810，控制口 8811）
跑通过。拓扑是照抄 `real-nginx-probe.yaml` 只换端口，命令与上面完全同形：

```
> python -m ced scan --topology <临时拓扑> --limit 8 --out <临时>/real.md
--------------------------------------------------------------
[结果] 用例 8 | 实现对 5 | 耦合误差 2 | 安全级 2
  [!!] 8b2611d2  ref-cl-first ↔ ref-lenient-cl  framing_boundary  最小化 59→42B
  [!!] 8b2611d2  customer-gateway ↔ ref-lenient-cl  framing_boundary  最小化 59→42B
[产物] <临时>/real.md
[产物] results/pocs  （1 个端到端 PoC 脚本）
        results\pocs\poc_8b2611d2.py
```

这条输出本身就是一次**自洽性证明**：中继逐字节透传，所以 `customer-gateway`（链路观测）
与本地 `ref-cl-first`（进程内基线）得到了**完全一样的**分歧结果
（`8b2611d2` 在两组对照里都出现，且最小化结果同为 59→42B）——
说明 `runner=chain` 这条路径没有引入观测偏差。

链路不可用时**实测**的输出（把 endpoint 指到一个没人监听的口）：

```
[!] 链路不可用，已中止（不产出任何结论）：前置 127.0.0.1:8199 不可达：[WinError 10061] 由于目标计算机积极拒绝，无法连接。
（退出码 1；报告文件不会被写出来）
```

**实测**：第二档那个「重建」到底建出了什么（用 `wsgiref` 顶替 gunicorn 跑
`docker/backend/app.py`，假探针抓字节；environ 里 `CONTENT_LENGTH=5` 且
`HTTP_TRANSFER_ENCODING=chunked`）：

```
POST /x?a=1 HTTP/1.1
x-forwarded-for: 1.2.3.4
Host: 127.0.0.1:8890
Content-Length: 5                              ← gunicorn 的定帧结论（它读到的体长）
X-CED-Orig-Content-Length: 5                   ← 回带原始值，证据不丢
X-CED-Orig-Transfer-Encoding: chunked          ← 出现不了就说明 gunicorn 把 TE 吞了
X-CED-Observed-By: gunicorn-wsgi
Connection: close

HELLO
```

注意两点，与 README 正文里的口径一致：头名被强制成小写（environ 里没有大小写）、
`Transfer-Encoding` 已经在 gunicorn 那层被解掉（这里按 WSGI 规范重新给 `Content-Length`），
所以段2 的观测是**语义级**的。

---

## 核验清单（原「本机没有 Docker —— 未验证清单」）

> 下表是**装 Docker 之前**的状态；装好之后的逐条结论见紧随其后的「实机验证记录」。

| # | 未验证项 | 具体是什么 | 怎么验 |
|---|---|---|---|
| 1 | compose 语法 | `docker-compose.yml` 只做过 YAML 解析（`yaml.safe_load` 通过），**没有** `docker compose config` | `docker compose config -q`（+ `--profile gunicorn`） |
| 2 | nginx 配置语法 | `nginx.conf` / `nginx-gateway.conf` 里的 `upstream`、`log_format`、`$http_content_length` 等**全部没被 nginx 解析过** | `docker compose run --rm front nginx -t` |
| 3 | 镜像构建 | `docker/probe/Dockerfile`（上下文=`..`）与 `docker/backend/Dockerfile`（要 pip 装 gunicorn）从没构建过 | `docker compose --profile gunicorn build` |
| 4 | 端口连通 | 8080→80、8081→8081、8090→8090、8801→8801 的映射与 `probe` 的 `expose: 8800` 内部可达性都没实测 | `docker compose up -d` 后主机 `curl http://127.0.0.1:8801/health` / `curl http://127.0.0.1:8080/` |
| 5 | nginx 实际定帧行为 | 尤其「客户端同时给 CL 与 TE 时 nginx 是转发还是 400」「chunked 体是否被改成 CL」——**不同版本行为不同**，配置注释里明确标了「以现场实测为准」 | `docker compose logs front`（本配置把请求行与 CL/TE 打进日志）+ 探针 `GET /views` |
| 6 | **真 gunicorn** 环境 | `docker/backend/app.py` 的重建/转发逻辑在本机用 `wsgiref`（标准库 WSGI 服务器）顶替 gunicorn 验证过（见下节），但**真 gunicorn** 下 environ 里 `CONTENT_LENGTH`/`HTTP_TRANSFER_ENCODING`/`wsgi.input_terminated` 到底长什么样、`--workers 1` 的日志形态，都没跑过 | `docker compose --profile gunicorn up -d` 后 `curl -v http://127.0.0.1:8090/`，应回 environ 的 JSON |
| 7 | 脚本运行时行为 | 三个 `.ps1` 只做过 **PowerShell 语法解析**（`Parser::ParseFile`，0 错误）与 BOM 检查，没在 Docker 环境里执行过 | 直接跑 `up.ps1` / `down.ps1` / `snapshot.ps1` |
| 8 | `--forwarded-allow-ips` | 用固定 IP `172.28.0.3` 是否被 gunicorn 接受、XFF 是否真的生效 | ⚠️ 已实测且**原假设有误**：固定 IP 被接受，但这个开关**不改写 `REMOTE_ADDR`**（只控制 secure header）—— 见「实机验证记录」与下面「第二档」小节 |

### 实机验证记录（2026-10-02，装有 Docker Desktop 4.93 的开发机）

环境：Docker Desktop **4.93.0** / 引擎 **29.8.1** / compose **v5.5.1**，程序装在 `F:\docker\DockerDesktop`、
镜像与容器数据根 `F:\docker\wsl`（实测落位：`disk\docker_data.vhdx` 1.57GB + `main\ext4.vhdx` 0.09GB），
引擎镜像源 `docker.m.daocloud.io` + `docker.1ms.run`；WSL **3.0.1**。

| # | 结论 | 实测要点 |
|---|---|---|
| 1 | ✅ | `docker compose config -q`（默认与 `--profile gunicorn`）都通过 |
| 2 | ✅ | `front` 与 `gateway` 两份 nginx 配置 `nginx -t` 都是 `test is successful` |
| 3 | ✅ | `docker compose --profile gunicorn build` 成功：`ced/probe:dev` 200MB、`ced/backend:dev` 199MB（容器内 `pip install gunicorn` 走 pypi 直连，通） |
| 4 | ✅ | 8080→80 / 8081→8081 / 8090→8090 映射正常；`curl 127.0.0.1:8801/health` → `{"status":"ok"}`；`curl 127.0.0.1:8080/` 回的就是探针观测 JSON |
| 5 | ⚠️ 实测到与预期不同的行为 | 见下「nginx 1.25.5 的定帧实测」 |
| 6 | ✅（含一处更正） | 真 gunicorn **23.0.0** 跑通（8090 直连 0.01s 返回探针观测）；`--forwarded-allow-ips` 的作用被更正，见下 |
| 7 | ⚠️ 两个发现 | ①**必须 `-ExecutionPolicy Bypass`**：默认 Restricted 策略下 `-File` 直接被拒（`Get-ExecutionPolicy -List` 各作用域均为 Undefined = 客户端默认 Restricted）；②`snapshot.ps1` 另有真 bug：`$PSScriptRoot` 在 **param 默认值**里是空的，`Join-Path` 直接报错、脚本根本起不来（`up.ps1`/`down.ps1` 只在函数体里用它，故不受影响）—— 已把默认值改到函数体里算。修完后三个脚本全部实机跑过：`up.ps1` 起栈并等到探针 ready；`down.ps1` 清干净；`snapshot.ps1` 存出 3 个 tar + manifest（sha256），`-Verify` 逐条 `[OK]` |
| 8 | ❌ 文档原假设有误 | 同第 6 项：`--forwarded-allow-ips` 不改写 `REMOTE_ADDR` |

#### nginx 1.25.5 的定帧实测（第 5 项，`docker compose logs front` + 探针 `/views`）

| 用例 | 客户端看到 | 探针收到（= nginx 转发出去的） |
|---|---|---|
| 基线 `GET` | 200（5.0s） | `framing_source: none`，`raw_len=128`（nginx 重写过请求：加了 Host / Connection / X-CED-Observer） |
| **`Content-Length` 与 `Transfer-Encoding` 并存** | **400，0.0s —— nginx 自己回绝** | **一个字节都没收到** |
| 仅 `Transfer-Encoding: chunked` | 200（5.0s） | **`te: []`、`cl: 5`** —— chunked 体被解开、按 CL 重发 |
| 仅 `Content-Length: 5` | 200（5.0s） | `cl: 5` |
| `Content-Length: 05`（前导零） | 200（5.0s） | **`cl: 5`** —— 前导零被归一化 |

结论：**CL+TE、chunked 体、CL 前导零这三类分歧在这台 nginx 之后根本观测不到** ——
它们在上游侧就被抹平了（这正是「前置定帧行为决定你能观测到什么」的实证）。
每条用例 5.0s = 探针的 `IDLE_TIMEOUT`：nginx 不半关闭，探针只能靠空闲超时判定输入结束。

#### gunicorn 23.0.0 的 `--forwarded-allow-ips`（第 6/8 项）

同一条请求（伪造 `X-Forwarded-For: 1.2.3.4` + `X-Forwarded-Proto: https`，对端 `172.28.0.1`）对照：

| `--forwarded-allow-ips` | 对端是否受信 | `REMOTE_ADDR` | `wsgi.url_scheme` |
|---|---|---|---|
| `172.28.0.3`（本栈的设定） | 否 | `172.28.0.1`（真实对端） | `http` |
| `172.28.0.1` | 是 | `172.28.0.1`（**仍是真实对端**） | `https` |

**这个开关只管 secure header，不管 `REMOTE_ADDR`。** 原文里「用 `/environ` 的 REMOTE_ADDR
前后对比就能看到差别」是错的；上面「第二档」小节已按实测更正。

#### 本轮实测暴露并已修掉的四个缺陷

1. **compose 固定 IP 冲突（必现）**：原先只给 `gateway`/`backend` 写了 `ipv4_address`，
   而先启动的 `probe`/`front` 会被动态分到 `.2`/`.3` —— 之后 `gateway` 想按固定地址起在 `.3` 上直接
   `failed to set up container networking: Address already in use`（`front` 必然早于 `gateway` 启动，故必现）。
   改成**四个服务全部钉死**（probe .2 / gateway .3 / backend .4 / front .5）。
   注意 `ipam.aux_addresses` **不是**解法：它的语义是「这个地址被别的东西占了」，写进去后
   `backend` 自己申请 `.4` 也会撞（实测过）。
2. **链路器吃不下真 nginx 的「客户端立即半关闭」**：链路器发完即 `SHUT_WR`（替身前置会把它透传给探针，
   所以又快又对），但 nginx 1.25.5 遇到客户端立即半关闭时**既不转发也不回响应**
   （实测：探针记到 `raw_len=0` 的空连接，客户端 0.0s 断开）→ 整轮链路扫描以「链路不可用」中止。
   修法：先试半关闭（替身前置的快路径），失败自动换成普通客户端模式并**记住**
   （真 nginx 只多花一次连接；不半关闭时每条用例约 5s）。回归测试见
   `ced/tests/fixtures/nginx_like_front.py` + `test_chain_e2e.py`。
3. **消融候选被拒会崩掉整轮扫描**：真前置会拒掉一部分消融候选（nginx 抹掉 `Content-Length` 后直接 400），
   而 `ProbeRejected` 原先只在**主观测**处被捕获 → 消融阶段一抛异常，整轮扫描带 traceback 崩掉。
   修法：抽共用的 `classify.upgradability.still_diverges`，候选被拒时**保守返回「分歧仍在」**
   （即该候选不算承载者，宁愿少升级也不凭空造可控性证据）；最小化谓词同样处理。
   回归测试见 `test_pipeline.py::TestAblationGuard`。

4. **把「前置静默丢弃某条请求」误判成链路故障**：真 gunicorn 对裸 LF 分行、大写块长（`0A`）
   这类它不认的写法，**既不转发、也不回响应**（实测：同一批 33 条语料里有 4 条如此）。
   而链路器原来把「没转发 + 没回响应」一律当链路故障 → 第二档拓扑的扫描跑到半路就中止
   （`--limit 12` 跑 138s 后崩在第 22 条）。修法：这种情况再发**一条最小正常请求**复探活性 ——
   探针还能记到视角 = 链路活着 = 这条只是「该前置不接受」，跳过并计数；复探也拿不到视角
   = 链路真坏了，仍然中止。两条测试把这条边界钉住（`silent_drop_front.py` 与「前置活着但上游不通」）。

#### 续测（2026-10-03）：原「仍未覆盖」三项的结论

| 原缺口 | 结论 |
|---|---|
| 真实客户产品接入 | ✅ 机制已验证（换 haproxy，零代码改动，出安全级发现 + PoC）—— 见下「换一种客户产品」 |
| `real-nginx-gunicorn.yaml` 端到端扫描 | ✅ 跑通：`用例 12 | 实现对 14 | 耦合误差 55 | 安全级 1`，约 620s；报告 `results/real-gunicorn.md` |
| `snapshot.ps1 -Load` 断网恢复 | ✅ 跑通：`down.ps1` → `docker rmi` 三个镜像（只剩 python 基础镜像）→ `-Load` 逐条校验 sha256 后全部恢复 → `up.ps1` 用恢复出来的镜像起栈成功 |

仍**未**覆盖：客户现场的真实产品（版本与配置各异 —— 下面的对照表说明了对 CL+TE / chunked 的
处置是**版本相关**的，换产品要重跑）；以及第二档拓扑 `--limit 12` 要跑约 10 分钟这件事
（每条用例受探针 5 秒空闲超时制约），现场演示请预留时间或调小 `--limit`。

#### 换一种客户产品：haproxy（可选扩展，已实测）

「接客户产品」不绑定 nginx —— 拓扑里 `runner: chain` 指向谁，引擎就观测谁转发出去的字节。
本机用第二种真实产品验过一遍，**不动任何代码**，只加一个容器 + 一个临时拓扑：

```yaml
# haproxy.cfg —— 挂到 /usr/local/etc/haproxy/haproxy.cfg
global
    maxconn 256
defaults
    mode http
    timeout connect 3s
    timeout client 30s     # 探针靠 5 秒空闲超时判定输入结束，别让 haproxy 先断链
    timeout server 60s
    option httplog
    log stdout format raw local0
frontend ced
    bind *:80
    default_backend cedprobe
backend cedprobe
    server probe probe:8800
```

```
docker run -d --name ced-haproxy --network ced-bench_cednet --ip 172.28.0.6 ^
  -p 127.0.0.1:8082:80 -v <上面这个 cfg>:/usr/local/etc/haproxy/haproxy.cfg:ro haproxy:2.9-alpine
# 拓扑照抄 real-nginx-probe.yaml，只把 endpoint 换成 127.0.0.1:8082
python -m ced scan --topology <临时拓扑> --limit 6 --no-minimize
```

实测：`用例 6 | 耦合误差 4 | 安全级 2`，并生成 PoC。代表样本与判定：

```
POST / HTTP/1.1\r\nHost: localhost\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc
```

haproxy 把**重复的 `Host` 头**合并掉了 —— 它转发给后端的字节数比客户端发的**少 17 字节**
（`consumed`：haproxy 58 / 参照 75，差值正好是那条重复头），消融实验把承载者精确定位到那条
重复 `Host`，判定 security / CWE-444 / desync。

**顺带得到一张「同一份字节、两种真实产品」的对照表**（同一批用例喂给同一个探针）：

| 用例 | nginx 1.25.5 | haproxy 2.9 |
|---|---|---|
| 基线 GET | 转发，`framing_source: none` | 同 |
| CL 与 TE 并存 | **400，不转发** | **按 TE 转发**（`framing_source: te`，丢掉 CL） |
| 仅 chunked | **解成 CL 重发**（`te: []`、`cl: 5`） | **原样保留**（`te: [chunked]`） |
| CL 前导零 `05` | 归一化成 `5` | 归一化成 `5` |

这张表就是本项目的立论本身：**同一份字节、两个单独看都没问题的产品，读出的边界不一样**；
差异能不能变成漏洞，取决于它们后面接的是什么 —— 所以探针要放在后面看。

#### 仍未覆盖的三项

- **真实客户产品接入**（把 `runner: chain` 指向客户产品）—— 本机只有 nginx 这一种前置。
- **`real-nginx-gunicorn.yaml` 的端到端扫描**（第二档拓扑跑完整差分）—— 各段单独验证过，组合扫描未跑。
- **`snapshot.ps1 -Load` 的断网恢复**（现场断网场景）—— `snapshot.ps1` 的保存/校验方向未跑。

### 本机**实际**做过的验证（都在本开发机上执行过）

| 验证 | 结果 |
|---|---|
| 两个拓扑能被 `ced.orchestrate.topology.load` 读进来 | ✅ 见下方命令与输出 |
| 两个拓扑文件的 YAML 缩进/字段对齐 | ✅ 人工逐行核对（缩进错会解析失败或字段丢失，而 `load` 会直接**报错**：`chain` 引用未定义实现会抛异常）；也确认了 `notes`/`image` 里的中文与 `:` 都已加引号 |
| compose 里的跨文件约定 | ✅ 人工核对：compose 的 `ports` 与两个拓扑的 `endpoint`/`probe_api`、`snapshot.ps1` 的镜像名、`backend` 的 `--forwarded-allow-ips` 固定 IP 与 `ipam`/`ipv4_address` 一致 |
| `docker-compose.yml` 能被 YAML 解析、服务/端口/profile/healthcheck 字段都在 | ✅ `yaml.safe_load` 通过，`services: backend, front, gateway, probe`；`gateway`/`backend` 在 profile `gunicorn` 里 |
| 三个 `.ps1` 语法 | ✅ `[Parser]::ParseFile` 0 错误（up 36 / down 8 / snapshot 16 条顶层语句），UTF-8 BOM 已加（Windows PowerShell 5.1 读中文注释需要 BOM） |
| `docker/backend/app.py` 语法 | ✅ `python -m py_compile` 通过 |
| `docker/backend/app.py` 两条路径（用 `wsgiref` 顶替 gunicorn，非 gunicorn 本身） | ✅ 转发模式：响应体 = 探针的观测 JSON（`cl=5, body_len=5, consumed=181`）；纯 environ 模式：回 environ 关键字段 JSON；重建出的原始字节逐行核对无误（见下） |
| chain 管道端到端（探针 + 中继前置 + CLI + 报告） | ✅ 「本机实测的输出」一节，退出码 0 |
| 链路不可用的行为 | ✅ 输出见上，退出码 1，不写报告 |
| 每条链路用例的延迟 | ✅ 实测：中继传递半关闭 **0.004 s**；中继不传递半关闭 **5.024 s**（探针 `IDLE_TIMEOUT = 5.0`） |

两个拓扑的实际加载结果（这就是验收命令的输出）：

```
> python -c "from ced.orchestrate.topology import load; t=load('ced/topologies/real-nginx-probe.yaml'); print(t.domain, t.chain); [print(s.impl_id, s.runner, s.endpoint, s.probe_api, s.image) for s in t.impls]"
http1-framing ('customer-gateway', 'ref-cl-first')
customer-gateway chain 127.0.0.1:8080 127.0.0.1:8801 nginx:1.25-alpine
ref-cl-first local None None None
ref-te-first local None None None
ref-lenient-cl local None None None

> python -c "...load('ced/topologies/real-nginx-gunicorn.yaml')..."
http1-framing ('nginx-gunicorn', 'ref-cl-first')
customer-gateway chain 127.0.0.1:8080 127.0.0.1:8801 nginx:1.25-alpine
nginx-gunicorn chain 127.0.0.1:8081 127.0.0.1:8801 ced/backend:dev
gunicorn-backend chain 127.0.0.1:8090 127.0.0.1:8801 ced/backend:dev
ref-cl-first local None None None
ref-te-first local None None None
ref-lenient-cl local None None None
```

---

## 第二档：gunicorn 与 `--forwarded-allow-ips`

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File docker/up.ps1 -Gunicorn      # = compose --profile gunicorn up -d --build
# 段2 入口在 8081（nginx gateway），它把请求转给 8090 的 gunicorn，
# gunicorn 再把"它自己解析出来的请求"重建后转给 8800 的探针。
python -m ced scan --topology ced/topologies/real-nginx-gunicorn.yaml --limit 12 --out results/real-gunicorn.md
```

**观测口径不同，读报告时别混**：

- 段1（`customer-gateway`，8080）：nginx 逐字节转发 → 探针的观测是**字节级**的
- 段2（`nginx-gunicorn`，8081）：中间隔了一个 WSGI 服务器，environ 里拿不到原始字节，
  由 `docker/backend/app.py` 把「gunicorn 的视图」重建后转给探针 → 观测是**语义级**的。
  重建时把原始 `Content-Length` / `Transfer-Encoding` 回带到 `X-CED-Orig-*` 头上，证据不丢。
- `gunicorn-backend`（8090）是**绕过 nginx** 直连 gunicorn 的观测点，用来区分
  「分歧是 nginx 引入的还是 gunicorn 引入的」。

**`--forwarded-allow-ips`（这段是给部署的人看的，不是给攻击者看的）**

⚠️ **本机实测更正（gunicorn 23.0.0）**：这个开关**不改写 `REMOTE_ADDR`**，它只决定 gunicorn 是否采信受信对端发来的 **secure header**（`X-Forwarded-Proto` → `wsgi.url_scheme`）。
实测对照（同一条请求：伪造 `X-Forwarded-For: 1.2.3.4` + `X-Forwarded-Proto: https`，对端 `172.28.0.1`）：

| `--forwarded-allow-ips` | 对端是否受信 | `REMOTE_ADDR` | `wsgi.url_scheme` |
|---|---|---|---|
| `172.28.0.3`（本栈的设定） | 否 | `172.28.0.1`（真实对端） | `http` |
| `172.28.0.1` | 是 | `172.28.0.1`（**仍是真实对端**） | `https` |

即：**`REMOTE_ADDR` 永远是 socket 对端**，无论有没有 XFF、对端受不受信；想拿客户端地址只能自己解 `environ['HTTP_X_FORWARDED_FOR']`，并且必须处理「最左边那一段是攻击者自己填的」。

- 本栈的做法：把 nginx(gateway) 的容器 IP **固定**成 `172.28.0.3`（compose 里的
  `ipam` + `ipv4_address`），然后 `CED_FORWARDED_ALLOW_IPS=172.28.0.3`。
  验证方式：带 `X-Forwarded-Proto: https` 请求 `http://127.0.0.1:8090/`，
  看回的 `environ['wsgi.url_scheme']` 是 `http` 还是 `https`（受信与否的差别只在这里，不在 `REMOTE_ADDR`）。
- **不要写 `*`**：那等于采信任何客户端伪造的 `X-Forwarded-For`，
  日志里的"攻击者地址"就变成攻击者自己填的字符串了。
- 若你的 gunicorn 版本不认 CIDR/不符合此处写法，就退回到**具体 IP 列表**（逗号分隔）；
  别用 `*` 图省事。访问日志 `docker compose logs backend` 里的请求行是 gunicorn
  自己解析出来的（`--access-logfile -`），排查"谁把这条请求读成了什么"先看它。

---

## 离线快照（比赛现场断网）

compose 正常起栈要联网：拉 `nginx:1.25-alpine`、pip 装 gunicorn。现场断网就全废，
所以**先在联网机器上**把镜像存成 tar：

```powershell
# 联网机器：先把两个自建镜像都构建出来（backend 在 profile 里，不带 profile 不会构建）
docker compose --profile gunicorn build

# 保存：docker save 到 docker/images/*.tar + 生成 manifest.txt（镜像:tag、文件名、sha256）
powershell -NoProfile -ExecutionPolicy Bypass -File docker/snapshot.ps1

# 校验（拷到 U 盘前后各跑一次，确认没拷坏）
powershell -NoProfile -ExecutionPolicy Bypass -File docker/snapshot.ps1 -Verify
```

```powershell
# 现场（断网机器）：先恢复镜像，再用 --no-build 起栈
powershell -NoProfile -ExecutionPolicy Bypass -File docker/snapshot.ps1 -Load
docker compose --profile gunicorn up -d --no-build
python -m ced scan --topology ced/topologies/real-nginx-gunicorn.yaml --limit 12 --out results/real-gunicorn.md
```

- `manifest.txt` 每行是 `<镜像:tag>\t<tar 文件>\t<sha256>`；`-Load` 会**先校验 sha256 再 load**，
  对不上就拒绝加载并报是哪个文件（拷贝损坏不会被当成"镜像坏了"）。
- 任何镜像不在本地，保存时会明确列出来并以非 0 退出 —— 半成品快照在现场会少一个服务。
- `docker/images/*.tar` 与 `manifest.txt` 被 `docker/images/.gitignore` 排除（体积大，不进仓库）。

---

## 常见问题

**1. 扫描慢得要命 / 一条用例 5 秒**
探针只有在**客户端半关闭写端**或自身空闲超时（`ced/probe/server.py` 的 `IDLE_TIMEOUT = 5.0`）
之后才处理一条请求，而 nginx **不会对上游半关闭**（它要留着连接读响应）。
本机用不传递半关闭的中继实测：**5.024 秒/条**；传递半关闭时 0.004 秒。
所以：**一定带 `--limit`**。第一档拓扑下只有 3 组对照里含真实前置，
`--limit 12` ≈ 12×3×5 ≈ 180 秒；先用少量用例把流程走通再放量。

**2. `docker compose up` 报端口被占用**
本开发机上 8080 就被 Steam（`steamwebhelper`）占着 —— 实测
`Get-NetTCPConnection -State Listen -LocalPort 8080` 能看到。`up.ps1` 会**先预检** 8080/8801
（第二档另加 8081/8090），占用就直接报出 PID 与进程名。
换端口时要**同时**改 `docker-compose.yml` 的 `ports` 和 `ced/topologies/real-*.yaml` 的 `endpoint`。

**3. `[!] 链路不可用，已中止（不产出任何结论）`**
这是**刻意设计**：前置不可达、或前置没转发任何字节时，引擎拒绝合成一个"被拒绝"的观测
（合成的观测必然与基线不同，会把探测失败变成成片假阳性）。先确认：
`powershell -File docker/up.ps1` 是否 ready、`curl http://127.0.0.1:8801/health`、
`docker compose ps` 里 `front` 是否在跑。

**4. 探针 `/views` 里有上一次的残留视角**
每次链路观测前引擎都会先 `POST /reset`（见 `ced/probe/chain.py`），所以正常不会串味。
但**不要并行跑两次扫描**：两个 runner=chain 的实现共用同一个控制口 8801。

**5. nginx 到底改了什么？（配置的解释）**
`docker/front/nginx.conf` 头部逐条列了：**没碰** `Content-Length` / `Transfer-Encoding`
（没有任何 `proxy_set_header` 去写它们）、**改了** `Host`、`Connection`、并新增了一个
`X-CED-Observer` 标记头。文件顶部明确写了这个 nginx 是「被观测的前置」而不是安全防护，
对它唯一的要求是「如实按自己的定帧策略处理」。

---

## 实机验证记录（2026-10-11，Windows 11 开发机，引擎 29.7.2）

另一台开发机（无预装镜像、走 Docker Hub + 系统代理 `127.0.0.1:10090`）从零起栈复跑，
全部数字为当日实测：

**环境坑（复现时先看）**

1. Docker Hub 直连被 DNS 污染（`auth.docker.io` 解析到无效 IP）→ Docker Desktop
   `settings-store.json` 需手动代理（键名大小写敏感：`ProxyHTTPMode` /
   `OverrideProxyHTTP(S)`，写错大小写静默不生效）；daemon 侧表现为
   `HTTPProxy = http.docker.internal:3128`。
2. `%USERPROFILE%\.docker\config.json` 的 `credsStore: desktop` 在 docker CLI 不在
   PATH 时会让 pull 报 `docker-credential-desktop not found` → 删掉该键即可拉公共镜像。
3. **宿主 8080 被占时回环连接会被抢占**：本机 Burp 监听 `127.0.0.1:8080`，而 compose 把
   front 发到 `0.0.0.0:8080` —— Windows 上更具体的回环绑定赢，`curl 127.0.0.1:8080`
   打进的是 Burp 不是 nginx。用临时 override 把 front 映到空闲端口即可。
4. compose 文件挂载在容器重建前可能拿到空文件（`default.conf` 0 字节）→
   `--force-recreate front` 后恢复正常（3763 字节）。

**实测发现（与模型口径的差异，全部是真实产品行为）**

| # | 实测 | 含义 |
|---|---|---|
| 1 | 26 条 security 级最小样本（results/pocs）发给第一档真实 nginx：**全部 400/501 拒绝、零转发** | 第一档（纯 nginx）无走私面；security 结论的适用前提是「前置放行」 |
| 2 | `Transfer-Encoding: xchunked` → nginx 回 **501**（不是 400） | 拒绝状态码口径要按实测写 |
| 3 | `Transfer-Encoding: Chunked`（大小写变体）+ 合法 chunk 体：nginx 接受，**重定帧为 `CL: 5` 转发 114 字节**（模型按"透传已解析字节"记账是 79 字节） | 真实前置会改写请求，"前置转发字节数"的模型口径对会改写的前置不成立 —— 对照必须按字段（`framing_source`/`cl`/`consumed`）做，正是扫描链路已采用的做法 |
| 4 | **客户端半关闭且请求体在途时，nginx 取消转发**（探针只记录到空连接；不半关闭则正常转发） | PoC 的 `--chain` 实机取证因此**不半关闭**，等响应/空闲超时 |
| 5 | `Content-Length: 03`（带 Host 头）→ nginx 接受、归一化 `cl: 3` 转发 | 与 2026-10-02 记录一致 |

**PoC 实机取证（`--chain`）**

```
python results/pocs/poc_984d5316.py --chain http://127.0.0.1:8801 --front 127.0.0.1:18080
  → 模型预测前置转发 0 字节（按自身策略拒绝）；真实 nginx 1.25.5 确实拒绝、探针零视角
  → verified: real-chain（exit 0）
python results/pocs/poc_8b2611d2.py --chain http://127.0.0.1:8801 --front 127.0.0.1:18080
  → 模型预测转发 39 字节，真实 nginx 拒绝 → 明确 MISMATCH 报告（exit 1，不伪造通过）
```

**第二档复跑**：`scan --topology real-nginx-gunicorn --limit 12` → 13 用例 / 前置拒绝
126 条 / 33 分歧 / **2 安全级**（`8b2611d2`、`984d5316`，均为参照对；真实产品对
`nginx-gunicorn` / `gunicorn-backend` 的分歧判 unknown 待人工复核）。

**已知案例实机观测**：9 条分帧案例的 `real_obs` 字段（两档实采：拒绝状态码或转发后的
定帧字段）已写入 `ced/cases/known/*.json`，`python -m ced regression` 输出按来源分列。
