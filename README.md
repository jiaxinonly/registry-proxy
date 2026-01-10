# 🐳 Registry Proxy

一个轻量级、高性能的 **Registry 反向代理**，支持多上游注册表（如 Docker Hub、Quay.io 等），支持 HTTPS。

> ✨ 特别适合按流量计费的低配服务器

---

## 🌟 功能特性

- ✅ **多上游注册表支持**：通过不同域名代理到不同的后端 registry（如 `docker.your.com` → Docker Hub，`quay.your.com` → Quay.io）
- 🔐 **自动认证中继**：拦截 `401 Bearer` 认证请求，重写 `realm` 为本地 `/auth/token` 路由，再代理到原始认证服务
- 📦 **Blob 重定向代理**：当 registry 返回 CDN 重定向（如 AWS S3）时，自动通过代理拉取 blob 内容，避免客户端直连外部 CDN
- 🔒 **原生 HTTPS 支持**：内置 TLS 终止，无需额外 Nginx
- 📊 **健康检查接口**：`/healthz` 用于 Kubernetes 或负载均衡器探活
- 📝 **结构化日志**：清晰记录代理、认证、错误等关键路径
- ⚡ **异步非阻塞**：基于 FastAPI + HTTPX，高并发性能优异

---

## 🛠️ 快速开始

```bash
git clone https://github.com/jiaxinonly/registry-proxy.git
cd registry-proxy
cp config.example.yaml config.yaml
pip install -r requirements.txt
python main.py