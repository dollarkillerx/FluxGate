# FluxGate

[English](./README.md) · 中文

一个**带 WAF 和管理面板的反向代理工具** —— 单个 Rust 二进制,转发流量、终止
TLS(支持 Let's Encrypt / ACME 自动签发证书)、提供 Web 应用防火墙,全部通过一个
简洁的网页控制台管理(中文 / English / 日本語)。

![FluxGate](image.png)

## 功能

- 🔁 **反向代理** —— 站点与路径路由、负载均衡、WebSocket 与流式转发
- 🛡️ **WAF** —— 内置 **OWASP 核心规则集(CRS)**(SQL 注入、XSS、RCE、LFI/RFI、扫描器探测等),检测**请求行、请求头_与请求体_**;支持自定义 IP(IPv4 **+ IPv6**)/ 路径 / 方法 / 地区 / 限流 / **请求体** 规则、人机验证(challenge),以及管理台登录的 **按 IP 暴力破解锁定**
- 🌍 **按站点访问控制** —— 按**国家**封禁(GeoIP)、拦截**机房/云 IP**(ASN,≈"只放家宽")、或**仅允许 Cloudflare** 流量。绑定到站点,**即使 WAF 关闭也生效**;支持 Cloudflare 真实 IP(`CF-Connecting-IP`)
- 🔐 **TLS** —— SNI 按域名选证书 + **ACME(Let's Encrypt)HTTP-01 自动签发与续期**
- 📊 **数据分析** —— 实时 24 小时 QPS / PV / UV、延迟、错误率、访客国家分布、**设备/系统分布**,以及按站点的**流量统计**(总量 / 近 30 天 / 今日)
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
> 每个站点都有**高级选项** —— 上传上限(默认 500 MB)、上游超时(120 秒)、爬虫拦截,
> 以及 **IP 访问控制**(封禁国家、拦截机房/云 IP、仅 Cloudflare)。

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

## 性能

单个 Rust 二进制,无 sidecar。测试环境 Apple M5,`--release`。

**WAF 规则引擎** —— 每请求,单核:

| 检测阶段 | 正常请求(全规则跑) | 早命中 |
| --- | --- | --- |
| 请求行 + 请求头 | ~440 ns | ~210 ns |
| 请求体(默认 body 规则) | ~280 ns | ~190 ns |

**端到端反向代理** —— ApacheBench,3 万次 POST,并发 50,keep-alive,单机
(代理 + 上游同机):

| | 吞吐 | p50 / p99 | 结果 |
| --- | --- | --- | --- |
| WAF **关闭** | **~26,900 req/s** | 1 / 7 ms | 恶意请求体放行 |
| WAF **开启**(完整检测 + 请求体检测) | **~21,800 req/s** | 2 / 12 ms | **恶意请求体 → 403** |

请求体检测只读取有上限的 **64 KB** 前缀:POST 体里的 `…union select…from users`
这类注入会被 403 拦截,而更大的上传**仍然流式转发、不缓冲**(扫描窗口之外零拷贝)。
WAF 按路由生效 —— 未开启的路由**完全不付 WAF 开销**。
