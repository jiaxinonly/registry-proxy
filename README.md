# 🐳 Registry Proxy

一个轻量级、高性能的 **Registry 代理**，支持多上游注册表（如 Docker Hub、Quay.io 等），支持 HTTPS。

> ✨ 特别适合按流量计费的低配服务器

---

## 🌟 功能特性

- ✅ **多上游注册表支持**：通过不同域名代理到不同的后端 registry（如 `docker.your.com` → Docker Hub，`quay.your.com` → Quay.io）
- 🔒 **原生 HTTPS 支持**：内置 TLS 终止，无需额外 Nginx
- 🔐 **自动认证中继**：拦截 `401 Bearer` 认证请求，重写 `realm` 为本地 `/auth/token` 路由，再代理到原始认证服务
- 📦 **Blob 重定向代理**：当 registry 返回 CDN 重定向（如 AWS S3）时，自动通过代理拉取 blob 内容，避免客户端直连外部 CDN
- 📊 **健康检查接口**：`/healthz` 用于 Kubernetes 或负载均衡器探活
- 📝 **结构化日志**：清晰记录代理、认证、错误等关键路径
- ⚡ **异步非阻塞**：基于 FastAPI + HTTPX，高并发性能优异

## 🗃️ 支持的镜像仓库

本代理已验证支持以下主流 OCI 仓库：

|仓库名称|上游地址|
| ------------- | ---------------- |
| **Docker Hub** | `https://registry-1.docker.io`|
| **Quay.io**   | `https://quay.io`|
| **registry.k8s.io**| `https://registry.k8s.io`|


---

## 🛠️ 快速开始

```bash
git clone https://github.com/jiaxinonly/registry-proxy.git
cd registry-proxy
mv config.example.yaml config.yaml  # 自行修改域名或使用hosts、提供证书
pip install -r requirements.txt
python main.py
```
## 相关项目
[Docker-Proxy](https://github.com/dqzboy/Docker-Proxy)

[LightMirrors](https://github.com/NoCLin/LightMirrors)

[docker-proxy](https://github.com/trueai-org/docker-proxy)