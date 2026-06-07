# FluxGate

[English](./README.md) · 中文

一个高性能的**反向代理 + 可编程 WAF**,自带**管理控制台**,以单个 Rust 二进制
交付。FluxGate 转发真实流量、终止 TLS(SNI)、强制执行 Web 应用防火墙,并通过
JSON-RPC 接口和内嵌的 React 控制台统一管理。

- **Rust** 管理服务(`axum` + `tokio` + `hyper`),在 `/rpc` 暴露 **JSON-RPC 2.0**
  接口。
- **React + TypeScript** 控制台(Vite + Tailwind),三语(English / 中文 / 日本語),
  **编译进二进制**(`rust-embed`)——一个可执行文件同时提供 API、UI 和代理。
- **后端无任何 mock 数据。** 仪表盘、指标、日志、健康检查均来自真实数据源;配置
  从空开始,由运维创建并持久化到磁盘。

> 数据面是基于 `hyper` 的自研代理(不是 Pingora)。它实现了真实的路由、负载均衡、
> TLS/SNI、WebSocket 桥接、流式传输与 WAF 强制执行。

---

## 两个平面

FluxGate 在同一进程内运行**控制面**与**数据面**,共享状态,配置改动即时生效。

| 平面 | 内容 | 默认监听 |
| ---- | ---- | -------- |
| **控制面**(管理控制台) | JSON-RPC API + 内嵌 React UI,走 **HTTPS**,使用自动生成的自签证书 | `FLUXGATE_ADMIN_ADDR` = `127.0.0.1:8080` |
| **数据面 — HTTP** | 明文反向代理(以及 HTTP→HTTPS 跳转) | `FLUXGATE_PROXY_ADDR` = `0.0.0.0:80` |
| **数据面 — HTTPS** | TLS 反向代理,按 **SNI** 选择证书 | `FLUXGATE_PROXY_TLS_ADDR` = `0.0.0.0:443` |

> 80/443 是特权端口——需要 `sudo`,或把代理指到高端口:
> `FLUXGATE_PROXY_ADDR=0.0.0.0:8080 FLUXGATE_PROXY_TLS_ADDR=0.0.0.0:8443`。
> 管理控制台是 HTTPS + 自签证书,浏览器首次访问会告警——点击"继续"即可。

控制面(管理台)**不**经过 WAF,也**不**计入访问日志/指标——这些只属于数据面。

---

## 网站 → 路径

配置分两层,贴合真实站点的运维方式:

- **网站(Site)** 对应一个入站主机(如 `www.example.com`),承载**主机级**配置:
  **启用 TLS**、要提供的**证书**、**HTTP→HTTPS 跳转**、以及**默认 WAF** 开关。
- **路径(Route)** 是网站下的一条路径(如 `/api`),承载**路径级**配置:目标
  **后端(upstream)**,以及可覆盖的**路径级 WAF** 开关(默认继承网站设置)。

请求解析:`Host` → 启用的网站 → 最长前缀匹配的启用路径 → 负载均衡后的后端节点。

> 旧的扁平路由配置在启动时**自动迁移**:按 host 分组成网站(把 TLS/证书/跳转/WAF
> 提升到网站级)。

---

## 反向代理(数据面)

代理与控制台共享状态,改动即时生效,代理流量进入同一套仪表盘/日志/指标。它会:

- 用入站 `Host` + 最长前缀路径匹配启用的网站/路径;
- 按后端的策略(`round_robin` / `weighted` / `ip_hash`;`least_conn` ≈ 轮询)从
  该路径的**后端**里选一个健康节点;
- 终止 **TLS 并按 SNI 选证**——只有同时满足「网站启用 TLS」**且**「有匹配证书」
  才完成握手;优先用网站选定的证书,否则按域名匹配;
- 对启用了 TLS 且开启跳转的网站,**把 HTTP 308 跳转到 HTTPS**;
- 以**强制模式**运行 **WAF**:`deny` → 403;`challenge` → **托管 JS 工作量证明
  拦截页**,真实浏览器自动通过(签名 clearance cookie),不跑 JS 的 bot/扫描器
  被挡住;
- **流式**转发请求/响应体(SSE、大文件上传下载——不缓冲);
- 代理 **WebSocket / HTTP Upgrade**(转发握手,双向桥接连接);
- 给响应打上 `Server: FluxGate/1.0` 头(覆盖后端的),并写入真实访问日志。

```bash
# 先建一个网站(host app.example.com)+ 一条路径(/ → 后端 "web"),然后:
curl -H 'Host: app.example.com' http://127.0.0.1:8088/
# 命中 deny 规则会得到真实 403(当该路径开启了 WAF):
curl -H 'Host: app.example.com' http://127.0.0.1:8088/etc/passwd   # → 403
```

---

## 哪些是真实的

| 领域 | 来源 |
| ---- | ---- |
| **指标**(CPU / 内存 / 网络) | 通过 [`sysinfo`](https://crates.io/crates/sysinfo) 采集的主机遥测,每 3 秒一次 |
| **访问日志** | **数据面**服务的真实 HTTP 请求(环形缓冲 + JSONL 文件) |
| **仪表盘**(总请求数、QPS、活跃连接、流量、Top 路由) | 由访问日志缓冲 + 数据面在途计数派生 |
| **按路径分析**(`metrics.route`) | 某 host+path 近 24 分钟的真实 QPS / 延迟 p50·p99 / 错误率 |
| **后端健康** | 每个节点的真实 TCP 连接探测(每 10 秒 + 保存时立即);**遍历所有**解析地址(IPv4 **与** IPv6) |
| **WAF 命中数 / 事件 / 拦截** | 真实:数据面对每个代理请求求值;命中计数在引擎里,安全事件 + `metrics.waf` 均被记录 |
| **TLS 证书** | 真实密码学:`tls.cert.request`/`renew` 用 `rcgen` 生成真正的 ECDSA 密钥对 + X.509 证书;`tls.cert.upload` 用 `x509-parser` 解析真实 PEM。首次启动会种入一张默认自签证书。私钥文件以 `0600` 写入 `FLUXGATE_CERT_DIR`。 |
| **网站 / 路径 / 后端 / WAF 规则 / 证书 / 设置** | 运维管理的配置,持久化到 `FLUXGATE_DATA_FILE` |
| **ACME 自动签发** | 未接入——`tls.cert.request` 以本地自签证书作为替身(真实 ACME 需要公网域名 + 可达的挑战)。见 `docs/INTEGRATION.md`。 |

**WAF 引擎**(`crates/fluxgate-admin/src/waf.rs`)支持 `ip`(精确 + IPv4 CIDR)、
`path` / `method` / `header`(正则)、`rate_limit`(`prefix@Nr/s`,真实的按客户端
固定窗口、内存有界)。`geo` 需要 GeoIP 库,永不匹配。规则**一次性编译**(正则/CIDR
预构建、按优先级排序)成无锁快照;path 规则检查 **path + query** 且**百分号解码**
(`%2e%2e` 编码穿越也拦得住)。Rust `regex` 线性时间,攻击者提交的正则不会 ReDoS。
首个命中生效,否则回落默认动作。**数据面强制执行**;管理台永不被求值(不会把自己
锁在外面)。

**内置基线规则**覆盖危险方法、SQLi、NoSQLi、XSS、路径穿越/LFI、RCE、Log4Shell
(`${jndi:…}`)、CRLF、Web Shell、敏感文件、扫描器 UA、限速。还可以从 WAF 页一键
导入 **OWASP CRS 规则包**(OWASP Core Rule Set 的精选子集,Apache-2.0,或用
`waf.rule.import`),补充 SQLi/XSS/RCE/LFI/RFI/PHP/Java/SSRF/扫描器 等覆盖——零新
依赖(改写成正则规则)。

**日志保留:** 超过 `FLUXGATE_LOG_RETENTION_DAYS`(默认 **6** 天)的访问日志和 WAF
事件,会在启动时和每小时从内存与磁盘清理。

---

## 项目结构

```
fluxgate/
├── Cargo.toml                      # Rust workspace(parking_lot、rustls、hyper、rcgen…)
├── crates/
│   ├── fluxgate-core/              # 共享领域模型(serde):Site、Route、Upstream…
│   └── fluxgate-admin/
│       └── src/
│           ├── main.rs             # 启动:两个平面、后台任务、日志保留
│           ├── rpc.rs              # JSON-RPC 2.0 分发器 + 鉴权 + 方法注册表
│           ├── proxy.rs            # 数据面:路由、负载均衡、WAF 强制、WS/流式
│           ├── serve.rs            # TLS 服务 + SNI 证书解析器(带缓存)
│           ├── tls.rs              # 证书生成(rcgen)+ PEM 解析(x509-parser)
│           ├── waf.rs              # WAF 规则匹配引擎(+ 引擎侧命中计数)
│           ├── collector.rs        # 遥测、访问日志/事件缓冲、指标、健康探测
│           ├── state.rs            # AppState(parking_lot 互斥锁)+ Config
│           └── persist.rs          # 配置加载/保存(+ 旧扁平路由→网站迁移)
└── web/                            # React 管理控制台(内嵌进二进制)
    └── src/{api,components,context,hooks,i18n,lib,mock,pages,types}
```

---

## 快速开始

```bash
# 1. 构建前端(输出到 web/dist,被二进制内嵌)
cd web && npm install && npm run build && cd ..

# 2. 运行——管理台走 HTTPS;代理用高端口避免 sudo
FLUXGATE_PROXY_ADDR=0.0.0.0:8088 FLUXGATE_PROXY_TLS_ADDR=0.0.0.0:8443 \
  cargo run -p fluxgate-admin
```

打开 **https://127.0.0.1:8080** 并接受自签证书。默认演示账号:`admin` / `admin`。

> 二进制在**编译期**内嵌 `web/dist`。改完前端后,需要重新 `npm run build` **并**
> 重新编译 Rust 二进制才会生效。

### 单个发布二进制

```bash
cd web && npm install && npm run build && cd ..
cargo build --release -p fluxgate-admin
sudo ./target/release/fluxgate-admin        # 绑定 :80/:443 需要 sudo
```

### 前端热重载

```bash
cargo run -p fluxgate-admin        # 终端 1
cd web && npm run dev              # 终端 2 → http://localhost:5173
```

Vite 把 `/rpc` 和 `/health` 代理到 Rust 服务。后端没起时,控制台会回退到仓库内的
mock(`web/src/mock/`);用 `VITE_USE_MOCK=true` 强制启用。

---

## 配置(环境变量)

| 变量 | 默认值 | 说明 |
| ---- | ------ | ---- |
| `FLUXGATE_ADMIN_ADDR` | `127.0.0.1:8080` | 管理台监听地址(走 **HTTPS**)。 |
| `FLUXGATE_PROXY_ADDR` | `0.0.0.0:80` | 数据面 **HTTP** 监听地址。留空 = 关闭。 |
| `FLUXGATE_PROXY_TLS_ADDR` | `0.0.0.0:443` | 数据面 **HTTPS**(SNI)监听地址。留空 = 关闭。 |
| `FLUXGATE_ADMIN_TOKEN` | `fluxgate-dev-token` | **JWT 签名密钥**。生产请务必更换。 |
| `FLUXGATE_ADMIN_USER` | `admin` | 初始登录用户名(仅首次;之后可在应用内修改)。 |
| `FLUXGATE_ADMIN_PASSWORD` | `admin` | 初始登录密码(仅首次;Argon2id 哈希后存储)。 |
| `FLUXGATE_DATA_FILE` | `fluxgate-data.json` | 配置持久化路径。留空 = 纯内存。 |
| `FLUXGATE_CERT_DIR` | `fluxgate-certs` | 证书 + 私钥 PEM 文件目录。 |
| `FLUXGATE_LOG_FILE` | `fluxgate-access.log` | 访问日志 JSONL 文件。留空 = 关闭。 |
| `FLUXGATE_EVENT_FILE` | `fluxgate-events.log` | WAF 事件 JSONL 文件。留空 = 关闭。 |
| `FLUXGATE_LOG_RETENTION_DAYS` | `6` | 访问日志 / WAF 事件保留天数(每小时 + 启动时清理)。 |
| `RUST_LOG` | `info` | 日志过滤(如 `fluxgate_admin=debug`)。 |

---

## 鉴权

控制台打开是**登录页**。默认演示账号:`admin` / `admin`。

- **登录是一次 JSON-RPC 调用**(`auth.login`,唯一无需 token 的方法);校验账号后返回
  一个**签名且会过期的 JWT**(HS256,8 小时,用 `FLUXGATE_ADMIN_TOKEN` 签名)。
- **密码用 Argon2id 哈希**——只持久化哈希。环境变量账号仅首次种入;两者都可在运行时
  修改(设置页 → `settings.update` / `auth.change_password`)。
- 其余方法都校验 JWT;失败返回 `-32001`,控制台回到登录页。

```bash
TOKEN=$(curl -sk -X POST https://127.0.0.1:8080/rpc -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"auth.login","params":{"username":"admin","password":"admin"}}' \
  | jq -r .result.token)
curl -sk -X POST https://127.0.0.1:8080/rpc -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":2,"method":"site.list"}'
```

---

## HTTP 端点与 JSON-RPC

| 方法 | 路径 | 说明 |
| ---- | ---- | ---- |
| `POST` | `/rpc` | JSON-RPC 2.0 接口。`auth.login` 公开;其余需 bearer token。 |
| `GET` | `/health` | 存活探针(公开)。 |
| `GET` | `/*` | 内嵌控制台 + SPA 回退。 |

```json
// 请求
{ "jsonrpc": "2.0", "id": 1, "method": "site.list", "params": {} }
// 成功
{ "jsonrpc": "2.0", "id": 1, "result": [ /* ... */ ] }
// 错误
{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32602, "message": "Invalid params" } }
```

### 方法列表

| 分组 | 方法 |
| ---- | ---- |
| Auth | `auth.login`(公开)、`auth.change_password` |
| Dashboard | `dashboard.summary`、`dashboard.traffic`、`dashboard.security_events` |
| Sites | `site.list`、`site.get`、`site.create`、`site.update`、`site.delete` |
| Routes | `route.list`、`route.get`、`route.create`、`route.update`、`route.delete`、`route.enable`、`route.disable` |
| Upstreams | `upstream.list`、`upstream.get`、`upstream.create`、`upstream.update`、`upstream.delete`、`upstream.health` |
| WAF | `waf.rule.list`、`waf.rule.get`、`waf.rule.create`、`waf.rule.update`、`waf.rule.delete`、`waf.rule.enable`、`waf.rule.disable`、`waf.event.list`、`waf.pack.list`、`waf.rule.import` |
| TLS | `tls.cert.list`、`tls.cert.get`、`tls.cert.request`、`tls.cert.renew`、`tls.cert.upload`、`tls.cert.delete` |
| Logs | `access_log.list`、`access_log.search` |
| Metrics | `metrics.system`、`metrics.traffic`、`metrics.route`、`metrics.upstream`、`metrics.waf` |
| Settings | `settings.get`、`settings.update`、`system.reload`、`system.info` |

错误码:`-32700` 解析 · `-32600` 无效请求 · `-32601` 方法不存在 · `-32602` 参数无效
· `-32603` 内部错误 · `-32004` 未找到 · `-32001` 未授权。

---

## 控制台页面

`仪表盘` · `网站`(主机 → 路径,可折叠,带按路径分析) · `后端服务` · `WAF 规则` ·
`TLS 证书` · `访问日志` · `监控指标` · `设置`。

特性:可搜索/排序表格(TanStack Table)、新建/编辑弹窗、危险操作二次确认、状态徽章、
toast、实时自动刷新、完整的加载/错误态、明暗主题。

---

## 持久化

配置改动(网站、路径、后端、WAF 规则、证书、设置、凭据)会快照写入
`FLUXGATE_DATA_FILE`(原子写)并在启动时重新加载;旧扁平路由配置会迁移成网站。
访问日志与 WAF 事件追加到各自的 JSONL 文件,启动时重载最近一段,故可跨重启保留。
主机遥测与后端健康是实时采样,不持久化。

---

## 构建、测试与部署

```bash
cargo test --workspace        # Rust 单元测试(WAF、TLS、auth/JWT、负载均衡、保留、SNI)
cargo fmt --all --check       # 格式(CI 强制)
cargo clippy --workspace      # lint

docker compose up --build     # 单容器:控制台 + 代理
```

CI(`.github/workflows/ci.yml`)在每次 push 和 PR 上跑 fmt + clippy + `cargo test`
以及前端类型检查/构建。

---

## 性能

在 release 构建(`cargo build --release`)、单机上实测。

**WAF —— 无锁、预编译规则集。** 规则一次性编译(正则 build、CIDR 解析、按优先级
排序)成不可变快照,通过 `Arc` 读取;请求路径上**零分配、零排序、零正则编译**。
对**完整基线 + OWASP CRS 规则包(32 条 regex/IP 规则)**做微基准
(`cargo test --release -- --ignored bench_evaluate`):

| 场景 | 单请求开销 | 单核吞吐 |
| ---- | ---------- | -------- |
| 良性(全部规则求值) | ~350 ns/req | ~280 万 req/s |
| 攻击(命中即返回) | ~190 ns/req | ~520 万 req/s |

端到端(`ab -k -c50`,同一后端)WAF **关 vs 开** 在噪声范围内(都 ~25k req/s,
0 失败)—— 亚微秒级的 WAF 开销被网络 + 后端延迟完全淹没(这里 ~25k 的天花板是
测试用的 Python 后端,不是代理)。注意:内置的 `2000 r/s` 限速规则会真实地拦截
单 IP 洪泛,所以微测 CPU 成本前要先关掉限速规则。

**其它热路径已优化:** 访问日志/指标的时间戳每条只解析一次(轮询不再重复解析、
不整份克隆);SNI 解析器按版本缓存解析后的证书(握手零读盘解析);访问/事件日志
用常驻 `O_APPEND` 句柄(每请求零 `open()`);共享状态用 `parking_lot` 互斥锁
(不毒化);WAF 命中计数在引擎内(热路径不写 Store);管理台请求完全不进代理的
指标/日志。

**仍存在的天花板。** 单一配置锁仍然守着路由(`pick_target` 每请求锁一次)、控制面
读取、以及持久化(在锁内序列化整个 Store)。高并发下这是吞吐天花板;下一步优化是
用 `arc-swap` 发布路由快照,让数据面无锁读。

---

## 说明与路线图

- **并发:** 共享状态使用 `parking_lot` 互斥锁(不会毒化)。单一配置锁是当前主要的
  扩展性瓶颈;下一步是用 `arc-swap` 路由快照实现数据面无锁读。
- **进程内终止 TLS**(rustls);SNI 解析器按证书版本缓存解析后的证书。
- 敏感操作写入审计日志(`tracing` target `fluxgate::audit`)。

## 许可证

MIT —— 见 [LICENSE](./LICENSE)。
