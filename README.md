# xquik_webhook_server

接收 [Xquik](https://xquik.com) 的 Webhook 推送，校验 **HMAC-SHA256** 签名后，通过 **SMTP**（默认 **465 / SMTPS**）将事件以 **HTML 邮件** 转发到指定邮箱。

## 功能概览

- `POST /webhook/xquik`：处理 Xquik 投递的 JSON，校验请求头 `X-Xquik-Signature`
- `GET /health`：健康检查
- 对重复投递（相同 body）做进程内去重，避免重复发信（多实例需自行换用 Redis 等）

## 环境变量

| 变量 | 必填 | 说明 |
|------|------|------|
| `WEBHOOK_SECRET` | 是 | Xquik 创建 Webhook 时提供的密钥 |
| `SMTP_HOST` | 是 | SMTP 主机名 |
| `SMTP_PORT` | 否 | 默认 `465`（隐式 TLS）；`587` 等为 STARTTLS |
| `SMTP_USER` | 是 | SMTP 用户名 |
| `SMTP_PASSWORD` | 是 | SMTP 密码或应用专用密码 |
| `MAIL_FROM` | 是 | 发件人地址 |
| `MAIL_TO` | 是 | 收件人，多个用英文逗号分隔 |
| `HTTP_ADDR` | 否 | 默认 `:8080` |
| `LOG_HEALTH` | 否 | 设为 `1` / `true` / `yes` 时，每次访问 `/health` 打印一行访问日志（默认关闭，避免健康检查刷屏） |

使用 Docker Compose 时，可在 `.env` 中设置 **`HTTP_PORT`**（默认 `8080`），用于映射宿主机端口，见 `docker-compose.yml`。

完整示例见仓库根目录 **[`.env.example`](.env.example)**。

```bash
cp .env.example .env
# 编辑 .env 填入真实配置
```

## 本地运行

需要 Go 1.22+。

```bash
go run .
```

## Docker

构建镜像：

```bash
docker build -t xquik-webhook-server:local .
```

### Docker Compose

1. 将 `docker-compose.yml` 中的镜像名改为你自己的镜像（或取消注释 `build` 段本地构建）。
2. 复制并填写环境变量：`cp .env.example .env`
3. 启动：

```bash
docker compose up -d
```

Webhook 对外地址需为 **HTTPS**（例如反向代理或隧道）。服务路径为 **`/webhook/xquik`**，在 Xquik 控制台填入完整 URL，并保证 `WEBHOOK_SECRET` 与控制台一致。

## GitHub Actions 与 Docker Hub

推送至默认分支或打 `v*` 标签时，工作流会构建 **linux/amd64、linux/arm64** 并推送到 Docker Hub。

在仓库 **Settings → Secrets and variables → Actions** 中配置：

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`（建议使用 Docker Hub 的 Access Token，而非账户密码）

镜像名默认为：`<DOCKERHUB_USERNAME>/xquik-webhook-server`，标签含 `latest`（默认分支）、semver（如 `v1.0.0`）及短 SHA。详见 [`.github/workflows/docker-publish.yml`](.github/workflows/docker-publish.yml)。

## 参考文档

- [Xquik llms.txt 索引](https://docs.xquik.com/llms.txt)
- [Webhook 签名校验](https://docs.xquik.com/webhooks/verification)
