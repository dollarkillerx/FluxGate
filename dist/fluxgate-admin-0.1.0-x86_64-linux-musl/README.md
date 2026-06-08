# FluxGate Admin — Linux x86_64 (static musl)

反向代理 + 可编程 WAF,内置 React 管理控制台(已打包进二进制)。

- 架构:`x86_64-unknown-linux-musl`,**静态链接**,不依赖 glibc,任何现代 x86_64 Linux 直接跑。
- 前端已嵌入二进制,无需单独部署。

## 快速开始

```bash
chmod +x fluxgate-admin

# 完整实例(管理台 + 反向代理 80/443)。绑特权端口需 root/sudo。
sudo FLUXGATE_ADMIN_ADDR=127.0.0.1:8791 \
     FLUXGATE_PROXY_ADDR=0.0.0.0:80 \
     FLUXGATE_PROXY_TLS_ADDR=0.0.0.0:443 \
     ./fluxgate-admin
```

启动后:

- 管理控制台:`https://127.0.0.1:8791/`(自签证书,浏览器需手动信任)
- 默认登录:`admin / admin`(请尽快在「设置」里改密码,或用 `FLUXGATE_ADMIN_PASSWORD` 启动时指定)

## 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `FLUXGATE_ADMIN_ADDR` | `127.0.0.1:8080` | 管理控制台(HTTPS)监听地址 |
| `FLUXGATE_PROXY_ADDR` | `0.0.0.0:80` | 反向代理 HTTP 面;留空 = 关闭 |
| `FLUXGATE_PROXY_TLS_ADDR` | `0.0.0.0:443` | 反向代理 HTTPS 面(SNI);留空 = 关闭 |
| `FLUXGATE_ADMIN_TOKEN` | `fluxgate-dev-token` | `/rpc` 的 JWT 签名密钥,生产务必改 |
| `FLUXGATE_ADMIN_USER` | `admin` | 登录用户名 |
| `FLUXGATE_ADMIN_PASSWORD` | `admin` | 登录密码 |
| `FLUXGATE_CERT_DIR` | `fluxgate-certs` | 证书/私钥 + ACME 账户存储目录 |
| `FLUXGATE_DATA_FILE` | `fluxgate-data.json` | 配置持久化文件;留空 = 仅内存 |
| `FLUXGATE_GEOIP_DB` | (自动下载) | GeoIP `.mmdb` 路径;不设则首启自动下载 |

## ACME 自动签发(Let's Encrypt,HTTP-01)

1. **前提**:域名解析到本机,且 **80 端口公网可达**(HTTP-01 验证从公网打 :80)。必须开启 `FLUXGATE_PROXY_ADDR=0.0.0.0:80`。
2. 控制台「设置 → ACME」:开启、填邮箱、勾选同意 ToS。
   - **联调先用 staging**:目录填 `https://acme-staging-v02.api.letsencrypt.org/directory`(生产目录有严格速率限制),验证 OK 再换生产。
3. 「证书 → 申请」填公网域名 → 证书先显示 `Pending`,后台 10–60s 签发完成自动变 `Valid`。
4. 证书到期前 30 天自动续期(每 12 小时检查一次),无需重启。

签发期间只接管 `/.well-known/acme-challenge/<token>` 路径,**不影响原站其它流量**。

## 健康检查

```bash
curl -k https://127.0.0.1:8791/health
```
