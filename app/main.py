# -*- coding: utf-8 -*-
"""
@FileName    : main.py
@Author      : jiaxin
@Date        : 2026/1/10
@Time        : 17:31
@Description :
Docker Registry 反向代理服务：
- 支持多上游注册表（如 Docker Hub、Harbor 等）
- 自动拦截 401 认证并重写 realm 到本地 /auth/token 路由
- 拦截 blob 重定向（3xx）并透明代理下载（避免客户端直连 CDN）
- 提供健康检查接口
"""

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from lib.settings import settings
from lib.schemas import HealthCheckResponse
from lib.logger import setup_logging
from urllib.parse import urljoin
from lib.utils import REALM_CACHE, handle_headers, handle_401_and_cache_realm, stream_download, stream_upload

# ======================
# 配置加载 & 日志初始化
# ======================
logger = setup_logging(settings)  # 初始化结构化日志系统

# 创建 FastAPI 应用实例
app = FastAPI(
    title="Registry Proxy",
    description="Docker Registry 反向代理网关，支持认证重写与 Blob 透明代理",
    version="0.0.1",
    docs_url="/docs" if settings.docs.enabled else None,
    redoc_url="/redoc" if settings.docs.enabled else None,
    openapi_url="/openapi.json" if settings.docs.enabled else None,
)


# ======================
# 健康检查端点
# ======================
@app.get("/healthz", response_model=HealthCheckResponse, summary="健康检查")
async def health_check():
    """返回服务运行状态，用于 K8s/Liveness Probe"""
    logger.debug("🩺 [健康检查] 收到探测请求")
    return HealthCheckResponse(status="ok", message="registry-proxy is running", version="0.0.1")


# ======================
# 认证令牌代理端点：/auth/token
# ======================
@app.get("/auth/token", summary="代理认证请求到上游")
async def auth_token(request: Request):
    """
    客户端在收到 401 后会请求此接口获取 token。
    本服务将：
    1. 根据 Host 头确定目标 upstream
    2. 从 REALM_CACHE 获取原始认证地址
    3. 代理请求（保留 query 参数如 service/scope）
    4. 返回上游响应（移除 content-encoding 防止 FastAPI 二次压缩）
    """
    proxy_domain = request.headers.get("host", "")

    if proxy_domain not in settings.upstreams:
        logger.error(f"❓ [认证] 收到未知代理域名请求 → Host: {proxy_domain}")
        return Response(status_code=400, content="未知的 registry-proxy 域名")

    upstream_base_url = settings.upstreams[proxy_domain]
    upstream_host = httpx.URL(upstream_base_url).host

    upstream_realm = REALM_CACHE.get(upstream_host)
    if not upstream_realm:
        logger.error(
            f"❓ [认证] realm 未就绪 → upstream_host: '{upstream_host}'。"
            "请先发起一次 /v2/ 请求以触发 401 并缓存 realm"
        )
        return Response(status_code=400, content="Realm 未就绪，请重试")

    upstream_full_url = upstream_realm
    if request.url.query:
        separator = "&" if "?" in upstream_realm else "?"
        upstream_full_url += separator + request.url.query

    logger.info(f"🔐 [认证] 代理请求至上游认证服务 → {upstream_full_url}")

    async with httpx.AsyncClient() as client:
        try:
            headers = await handle_headers(request.headers)
            resp = await client.get(upstream_full_url, headers=headers, timeout=15.0)

            resp_headers = await handle_headers(resp.headers)
            logger.info(f"✅ [认证] 上游返回状态码: {resp.status_code}")

            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=resp_headers
            )
        except Exception as e:
            logger.exception("🚨 [认证] 代理请求失败 → 检查网络或上游服务可用性")
            return Response(status_code=502, content="认证服务不可达")


# ======================
# 主代理路由：/v2/{path}
# ======================
@app.api_route("/v2/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"], summary="主代理入口")
async def proxy(request: Request):
    """
    核心代理逻辑：
    - 根据 Host 头路由到不同 upstream
    - 处理 401（重写 realm）
    - 处理 3xx 重定向：
        - 若路径含 /blobs/ → 流式代理（StreamingResponse）
        - 否则 → 代取内容并返回 200（隐藏重定向）
    - 其他响应直接透传
    """
    # 获取域名判断代理到哪个仓库
    proxy_domain = request.url.hostname

    if proxy_domain not in settings.upstreams:
        logger.warning(f"🌐 [代理] 收到未知域名请求 → Host: {proxy_domain}")
        return Response(status_code=400, content="未知的注册表域名")

    upstream_base_url = settings.upstreams[proxy_domain]
    upstream_host = httpx.URL(upstream_base_url).host
    upstream_full_url = upstream_base_url + request.url.path
    if request.url.query:
        upstream_full_url = upstream_full_url + "?" + request.url.query

    headers = await handle_headers(request.headers)
    logger.info(f"➡️ [代理] {request.method} {request.url} → {upstream_full_url}")

    async with httpx.AsyncClient() as client:
        try:
            if request.method == "PATCH":
                logger.info("📤 [代理] 检测到 blob 分块上传 → 启用流式上传")
                upstream_resp = await stream_upload(upstream_full_url, headers, request)
            else:
                upstream_resp = await client.request(
                    method=request.method,
                    url=upstream_full_url,
                    headers=headers,
                    content=await request.body(),
                    timeout=30.0
                )

            # === 情况1: 401 认证响应 ===
            if (
                    upstream_resp.status_code == 401
                    and upstream_resp.headers.get("www-authenticate", "").lower().startswith("bearer ")
            ):
                logger.info("🛡️ [代理] 拦截到 Bearer 认证请求 → 准备重写 realm")
                return await handle_401_and_cache_realm(upstream_resp, request)

            # === 情况2: 3xx 重定向 ===
            if upstream_resp.status_code in (302, 307):
                location = upstream_resp.headers.get("location")
                if not location:
                    logger.error("🔗 [代理] 3xx 响应缺少 Location 头 → 返回原响应")
                    return Response(status_code=upstream_resp.status_code, headers=dict(upstream_resp.headers))

                # 解析绝对 URL（处理相对重定向）
                resolved_location = urljoin(upstream_base_url, location)
                logger.info(f"🔗 [代理] 原始重定向: {location} → 解析后: {resolved_location}")

                # 判断是否为 blob 请求（关键！避免客户端直连 CDN）
                if "/blobs/" in upstream_full_url:
                    logger.info("📦 [代理] 检测到 blob 重定向 → 启动流式代理")
                    return StreamingResponse(
                        stream_download(resolved_location),
                        status_code=200,
                        media_type="application/octet-stream"
                    )
                else:
                    # Manifest 或 tag 列表等 → 代取内容，隐藏重定向
                    logger.info("🔄 [代理] 拦截非-blob 重定向 → 代取内容并返回 200")

                    async with httpx.AsyncClient() as cdn_client:
                        try:
                            cdn_resp = await cdn_client.get(
                                resolved_location,
                                timeout=30.0
                            )
                            cdn_resp_headers = await handle_headers(cdn_resp.headers)
                            return Response(
                                content=cdn_resp.content,
                                status_code=200,  # 隐藏 3xx，返回 200
                                headers=cdn_resp_headers
                            )
                        except Exception as e:
                            logger.exception(f"💥 [代理] 拉取重定向目标失败 → URL: {resolved_location}")
                            return Response(status_code=502, content="Failed to fetch redirected resource")

            # === 情况3: 普通响应（2xx/4xx/5xx）===
            upstream_resp_headers = await handle_headers(upstream_resp.headers)

            if upstream_resp.status_code == 202:
                location = upstream_resp_headers.get("location")
                try:
                    new_location = location.replace(upstream_host, proxy_domain)
                    logger.info(f"🔄 [代理] 重写 202 Location → {location} => {new_location}")
                    upstream_resp_headers["location"] = new_location

                    return Response(
                        content=upstream_resp.content,
                        status_code=202,
                        headers=upstream_resp_headers
                    )
                except Exception as e:
                    logger.exception(f"⚠️ [代理] 重写 Location 失败: {e}")

            logger.debug(f"📡 [代理] 上游响应 → Status: {upstream_resp.status_code}")
            return Response(
                content=upstream_resp.content,
                status_code=upstream_resp.status_code,
                headers=upstream_resp_headers
            )

        except Exception as e:
            logger.exception(f"🔥 [代理] 请求上游失败 → Target: {upstream_full_url}")
            return Response(status_code=502, content="网关错误（Bad Gateway）")


# ======================
# 应用启动入口
# ======================
if __name__ == "__main__":
    import uvicorn

    # 打印配置摘要
    logger.info("📚 已加载的上游注册表映射：")
    for proxy_domain, url in settings.upstreams.items():
        logger.info(f"  🌍 {proxy_domain} → {url}")

    ssl_args = {}
    if settings.https.enabled:
        if not settings.https.cert or not settings.https.key:
            raise ValueError("HTTPS 已启用，但配置中缺少 'cert' 或 'key'")
        ssl_args = {
            "ssl_certfile": settings.https.cert,
            "ssl_keyfile": settings.https.key
        }
        logger.info(f"🔒 启动 HTTPS 代理服务 → https://{settings.listen.host}:{settings.listen.port}")
    else:
        logger.info(f"🔌 启动 HTTP 代理服务 → http://{settings.listen.host}:{settings.listen.port}")

    uvicorn.run(
        app,
        host=settings.listen.host,
        port=settings.listen.port,
        reload=False,
        **ssl_args
    )
