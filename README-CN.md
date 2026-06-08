# FluxGate

[English](./README.md) · 中文

一个**带 WAF 和管理面板的反向代理工具** —— 单个 Rust 二进制,转发流量、终止
TLS(支持 Let's Encrypt / ACME 自动签发证书)、提供 Web 应用防火墙,全部通过一个
简洁的网页控制台管理(中文 / English / 日本語)。

![FluxGate](image.png)

## 功能

- 🔁 **反向代理** —— 站点与路径路由、负载均衡、WebSocket 与流式转发
- 🛡️ **WAF** —— 内置完善的 **OWASP 核心规则集(CRS)**(SQL 注入、XSS、RCE、LFI/RFI、扫描器探测等),并支持自定义 IP / 路径 / 方法 / 地区 / 限流规则与人机验证(challenge)
- 🔐 **TLS** —— SNI 按域名选证书 + **ACME(Let's Encrypt)HTTP-01 自动签发与续期**
- 📊 **仪表盘** —— 实时 24 小时 QPS / PV / UV、延迟、错误率、访客国家分布(GeoIP)
- 🖥️ **管理面板** —— 内嵌在二进制里,无需单独部署;界面三语

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
