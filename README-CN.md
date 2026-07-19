# FluxGate

[English](./README.md) · 中文

一个**带 WAF 和管理面板的反向代理工具** —— 单个 Rust 二进制,转发流量、终止
TLS(支持 Let's Encrypt / ACME 自动签发证书)、提供 Web 应用防火墙,全部通过一个
简洁的网页控制台管理(中文 / English / 日本語)。

![FluxGate](image.png)

## 功能

- 🔁 **反向代理** —— 站点与路径路由、负载均衡、WebSocket 与流式转发
- 🔀 **L4 / TLS-SNI 透传** —— 在共享的 `:443` 上按 **ClientHello 的 SNI** 匹配,把原始 TCP 流**逐字节**转发到源站,**从不终止 TLS** —— TLS 与应用层协议保持端到端(VLESS-**Reality**、**AnyTLS**,或任意自带 TLS 的后端)。SNI 支持**精确**与**单级通配**(`*.example.com`),源站按 **轮询 / 最少连接 / IP 哈希** 负载均衡。**未命中任何 L4 路由的 SNI 会回落到普通 L7 HTTPS 代理**,因此 L4 与 L7 **共用一个端口**。在控制台 **L4** 页面管理 —— 详见 [**L4 / TLS-SNI 透传**](#l4--tls-sni-透传)
- ↪️ **重定向** —— 按站点配置 **301 / 302** 规则:路径支持**精确匹配**或**前缀匹配**(`/old*`),跳转到完整 URL 或 `/路径`,在边缘直接返回、无需回源。另含一键 **HTTP→HTTPS**(308)重定向
- 🛡️ **WAF —— 语义化、结构感知** —— **12 个检测模块**,*解析每个请求值的结构*而非关键字匹配,具备 **libinjection 级**的 SQLi/XSS,外加 SSTI / NoSQL / XXE / 反序列化 / **PHP** 与 **Java-OGNL/SpEL** 注入,以及 **HTTP 请求走私**检测 —— 在抓住绕过变形的同时**大幅降低误报**。CRS 式**异常评分**、**按路由 监控/拦截** 模式、**误报一键转例外**。一层薄 regex 只负责 IP(IPv4 **+ IPv6**)/ 路径 / 方法 / 地区 / 限流 / **请求体** 等策略规则 + 虚拟补丁;人机验证;管理台 **按 IP 暴力破解锁定**。检测请求行、请求头**_与请求体_** —— 详见 [**Web 应用防火墙**](#web-应用防火墙)
- 🌍 **按站点访问控制** —— 按**国家**封禁(GeoIP)、拦截**机房/云 IP**(ASN,≈"只放家宽")、**仅允许 Cloudflare**、或**仅允许浏览器**(UA 白名单)。绑定到站点,**即使 WAF 关闭也生效**;支持 Cloudflare 真实 IP(`CF-Connecting-IP`)
- 🚫 **IP 黑白名单 + 自动封禁** —— 手动白名单(完全信任)与黑名单,外加可选**自动封禁**:某 IP 在 24h 内触发 _N_ 次 WAF 拒绝后封禁一段时间或永久。双栈(IPv4/IPv6),可一键解封
- 🔐 **TLS** —— SNI 按域名选证书 + **ACME(Let's Encrypt)HTTP-01 自动签发与续期**
- 📊 **数据分析 + 风险看板** —— 实时 24 小时 QPS / PV / UV、延迟、错误率、访客国家分布、**设备/系统分布**、按站点**流量统计**(总量 / 近 30 天 / 今日),以及**风险看板**(WAF 拦截 24h、恶意 UA Top、攻击来源国家)
- 🖥️ **管理面板** —— 内嵌在二进制里,无需单独部署;界面三语;品牌化的拦截 / 人机验证 / 404 页面

## 安装

```bash
curl https://raw.githubusercontent.com/dollarkillerx/FluxGate/refs/heads/main/install.sh | bash
```

就这一行。安装脚本(用 root 运行;非 root 请加 `sudo`)会:

1. 让你**选择语言**,再设置管理员**账户 + 密码**
2. 安装为 **systemd 服务**,代理监听 `:80` / `:443`,控制台监听一个**随机高端口**
3. 完成后打印**控制台地址、账户和密码**

之后再次运行同一条命令,会出现 **停止 / 重启 / 更新** 菜单
(`--update` 为零停机升级,失败自动回滚)。

> 控制台为自签 HTTPS 证书,浏览器首次访问需手动信任。ACME 自动签发需要域名解析到
> 本机且 80 端口公网可达。
>
> 每个站点都支持 **301 / 302 重定向规则**(路径精确匹配或 `/old*` 前缀匹配 →
> 完整 URL 或 `/路径`),在边缘于路由前直接返回。
>
> 每个站点还有**高级选项** —— 上传上限(默认 500 MB)、上游超时(120 秒)、爬虫拦截、
> 仅浏览器,以及 **IP 访问控制**(封禁国家、拦截机房/云 IP、仅 Cloudflare)。
>
> **基于 IP 的控制**(地域 / 机房 / 黑名单 / 自动封禁)判定的是真实客户端 IP —— 默认用
> socket 对端;只有开启了 **「仅允许 Cloudflare」** 的站点才从 `CF-Connecting-IP` 取真实
> 访客 IP(该开关同时锁定源站只收 CF 流量、并标记本站"套了 CF")。所以套了 CF 的站点请
> 把它打开才能拿到真实访客 IP;在**非 Cloudflare** 的反代之后取到的是反代 IP,请把反代加白名单,或优先用 Cloudflare / 直连。

## 从源码运行

```bash
cd web && npm install && npm run build    # 构建控制台(嵌入二进制)
cargo run -p fluxgate-admin               # 启动 FluxGate
```

启动后**管理台**在 **`https://127.0.0.1:8080/`** —— HTTPS 自签证书(浏览器点继续即可),
默认登录 **`admin` / `admin`**。反代数据面默认监听 `:80` / `:443`,本机开发可指到高端口避免 root:

```bash
FLUXGATE_PROXY_ADDR=127.0.0.1:8888 FLUXGATE_PROXY_TLS_ADDR= cargo run -p fluxgate-admin
```

**前端热更新**(可选):FluxGate 跑着的同时,另开终端 `cd web && npm run dev`,打开
**`http://localhost:5173/`**,它会把 `/rpc`、`/health` 代理到后端。GeoIP / ASN 库首启
自动下载(或用 `FLUXGATE_GEOIP_DB` / `FLUXGATE_ASN_DB` 指定)。

## L4 / TLS-SNI 透传

FluxGate 的多数路由是 **L7**:终止 TLS、解析 HTTP、跑 WAF、再回源。但有些后端
**不能被终止** —— 它们在原始 TCP 之上跑**自己的** TLS(VLESS-Reality、AnyTLS、
私有 mTLS 服务)。为此 FluxGate 提供 **L4 透传**。

一条 **L4 路由**声明一个或多个 **SNI** 名称。在共享的 `:443` 入口,FluxGate *只*
窥探 TLS **ClientHello** —— 仅够读出 SNI,绝不解密 —— 然后:

- **SNI 命中某条 L4 路由** → 把 ClientHello(逐字节)**以及**后续整个连接直接拼接
  转发到选中的源站。**从不终止 TLS**;客户端与源站照常完成端到端握手。
- **SNI 谁都不命中** → 把窥探到的字节回放进**普通的 L7 HTTPS 代理**(WAF、ACME、
  路由),一个字节不丢。

于是 L4 与 L7 **共用 443 端口** —— 无需第二个监听、无需倒腾端口。

匹配规则是**先精确、再取最具体的单级通配**(`*.example.com` 命中 `a.example.com`,
但不命中裸域名或 `a.b.example.com`)。每条路由列出一个或多个 `host:port` **源站**,
按 **轮询 / 最少连接 / IP 哈希** 负载均衡(IP 哈希会把同一客户端固定到同一源站 ——
对有状态的 TLS 协议很有用),连接超时可配置。

全部在控制台 **L4** 页面管理(或用 `l4route.*` RPC 方法):给路由起个名字、填 SNI、
填源站、选策略、打开开关即可。

## Web 应用防火墙

大多数 WAF 用宽泛的关键字正则匹配攻击 —— 既容易被绕过,又误报连连。FluxGate 以
**语义引擎**为主:它*解析每个请求值的结构*(解码 → 分词/解析 → 判断构造),正则只
保留它真正擅长的部分:策略与虚拟补丁。

- **结构感知检测 —— 12 个模块。** SQL 注入、XSS、路径穿越、命令注入、SSRF、协议
  (NUL/CRLF)、模板注入(SSTI)、NoSQL、XXE、反序列化、**PHP 函数注入**、**Java /
  OGNL / SpEL** 注入 —— 再加上传输层的 **HTTP 请求走私**(CL.TE / TE.CL)检测。
- **libinjection 级的 SQLi 与 XSS。** libinjection 的 SQLi 指纹引擎与 HTML5 XSS
  分词器的**逐字节纯 Rust 移植**,用 **30 万输入的差分测试** + 其自带的 oracle 向量
  对照原版 C 验证。
- **误报大幅降低。** `union select tutorial`(散文)、`shell_exec` 的*提及*都**不会**
  触发;而真正的 `' OR 1=1--` 或 `shell_exec(...)` **调用**会。检测**逐提取值**进行,
  payload 无法跨 `&`/`=` 边界"串味",且每个值先经多层解码。
- **异常评分(CRS 式)。** 一个请求上多个单独看很弱的信号会累加并升级动作 —— 抓住
  任何单条规则都抓不到的组合攻击。
- **运营闭环。** 按路由 **监控 / 拦截** 模式(灰度上线)、**误报一键转例外**、每条
  事件都有决策追踪。
- **正则只做策略,不做检测。** IP / 路径 / 方法 / 地区 / 限流 / 请求体规则、显式放行,
  以及对 0-day 的即时**虚拟补丁**。宽泛的 CRS *检测*规则已被语义引擎取代、默认禁用。
- **又快又稳。** ~2 µs/请求,热路径**无锁**(随核数线性扩展);检测器 panic 时 fail-open;
  请求体检测限定 64 KB 前缀,更大的上传流式转发、不缓冲。

### 攻防实测 —— 到底拦不拦得住?

引擎自带一套**红队基准**,作为回归守卫:覆盖全部 12 个模块的真实攻击 + 已知 WAF 绕过变形、
高度相似的良性流量,以及一组**硬核绕过**技巧。

| | 结果 |
| --- | --- |
| **攻击召回** | **81 / 81 命中(100%)** —— SQLi · XSS · RCE · 路径穿越 · SSRF · SSTI · NoSQL · XXE · 反序列化 · PHP · OGNL/SpEL,含注释/大小写/编码变形 |
| **误报** | **0 / 35** —— 散文(`union select tutorial`)、代码讨论(`how to use shell_exec`)、模板(`${user.name}`)、人名(`O'Brien`)、URL,全部干净放行 |
| **硬核绕过** | **13 / 14 命中** —— overlong-UTF-8 `%c0%af`、无空格 `${IFS}` 命令注入、`nip.io` 通配 DNS 打回环、双重/百分号编码、MySQL 版本化注释…… |

`100% 召回 + 0 误报` 是**被断言的**(永久守卫,不会悄悄退化);SQLi/XSS 另外用 **30 万输入
差分测试** + 模糊测试**逐字节对照 C 版 libinjection**。唯一记录在案的漏网(一个真实 HTTP 栈
都不会解析的 unicode 数字 IP)是**透明追踪、而非隐藏**——可复现的对抗测试,不是营销话术:

```bash
cargo test -p fluxgate-waf --release --test corpus -- --ignored --nocapture red_team
```

## 性能

单个 Rust 二进制,无 sidecar。测试环境 Apple Silicon 笔记本,`--release`,除注明外单核。
下面每个数字都可由仓库里的 `#[ignore]` 基准复现(命令附在表下)。

### 开启 WAF 每请求多花多少

语义引擎是**结构感知**的 —— 参数提取 → 多层解码 → 字节类预过滤 + 一趟共享
Aho-Corasick → 门控检测器 —— 所以良性热路径**零分配、无锁**(`ArcSwap` 无锁读配置)。
开 WAF 相比关 WAF,恰好多了 regex 规则一趟 + 语义一趟;关闭则完全跳过(多花 0):

| 开 WAF 每请求开销(OWASP-CRS 规则 + 全部 12 个语义模块) | 多花 |
| --- | --- |
| 良性 `GET`(regex + 语义,无命中) | **~1.9 µs** |
| 攻击 `GET`(SQLi,regex 规则早命中) | **~2.5 µs** |

<sub>`cargo test -p fluxgate-admin --release waf_overhead -- --ignored --nocapture`</sub>

语义分析是大头,而它**大部分根本不会在良性流量上运行**(预过滤门控把值挡在检测器之外):

| 语义分析(每请求) | 开销 |
| --- | --- |
| 良性(5 参数 + UA + 3 cookie → 约 18 个待检值) | ~1.2 µs |
| query 里的 SQLi | ~1.7 µs |
| 良性 JSON API 请求体(6 字段) | ~0.5 µs |

<sub>`cargo test -p fluxgate-waf --release --test corpus -- --ignored bench_semantic`</sub>

### 端到端吞吐 —— 关 WAF vs 开 WAF

真实代理走 TCP + mock 上游,32 条 keep-alive 连接 × 1500 次良性 `GET`(本地回环;
客户端、代理、上游共用同一运行时):

| | QPS | p50 | p99 |
| --- | --- | --- | --- |
| WAF **关闭** | ~52,000 | ~580 µs | ~1.0 ms |
| WAF **开启**(CRS + 全部语义模块) | ~51,000 | ~620 µs | ~1.1 ms |

<sub>`cargo test -p fluxgate-admin --release waf_qps -- --ignored --nocapture`</sub>

开/关之间的差距(多次运行约 0–10%)**落在这个 CPU 饱和回环环境的测量噪声内** ——
也就是说 WAF 多花的那 ~2 µs CPU,在 50k+ QPS 下已经小到无法和调度抖动区分开。真实
部署里上游往返是毫秒级、代理有独立 CPU,WAF 最多就是个位数百分比的开销。

WAF **按路由生效**(未开启的路由完全不付开销),良性热路径**无锁**,所以**随核数线性扩展**。
请求体检测只读取有上限的 **64 KB** 前缀:POST 体里的 `…union select…from users`
会被拦截,而更大的上传**仍然流式转发、不缓冲**(扫描窗口之外零拷贝)。
