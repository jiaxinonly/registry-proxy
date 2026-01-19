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

import re
from typing import AsyncGenerator
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from lib.settings import Settings
from lib.schemas import HealthCheckResponse
from lib.logger import setup_logging
from starlette.datastructures import Headers
from urllib.parse import urlparse, urljoin

# ======================
# 配置加载 & 日志初始化
# ======================
settings = Settings()
logger = setup_logging(settings)  # 初始化结构化日志系统

# 全局缓存：存储各 upstream host 对应的原始认证 realm
REALM_CACHE: dict[str, str] = {}

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
# 工具函数：流式代理 Blob 内容（用于处理 CDN 重定向）
# ======================
async def _stream_blob(url: str, original_headers: dict) -> AsyncGenerator[bytes, None]:
    """
    从给定 URL 流式拉取二进制内容（如 layer/blob），并透传给客户端。

    注意：
    - 不跟随重定向（由调用方确保 url 是最终 CDN 地址）
    - 使用 Host 头欺骗以绕过 CDN 的 Host 校验
    """
    parsed_url = urlparse(url)
    host = parsed_url.hostname
    if not host:
        error_msg = f"无效的重定向 URL：缺少主机名 | URL={url}"
        logger.error(f"❌ [BLOB代理] {error_msg}")
        raise ValueError(error_msg)

    # 构造请求头：关键是要设置正确的 Host 和 User-Agent
    cdn_headers = {
        "Host": host,
        "User-Agent": original_headers.get("user-agent", "registry-proxy/0.0.1"),
    }

    logger.info(f"📥 [BLOB代理] 开始流式拉取资源 → URL: {url} | Host: {host}")

    async with httpx.AsyncClient() as client:
        try:
            async with client.stream(
                    method="GET",
                    url=url,
                    headers=cdn_headers,
                    follow_redirects=False,  # 不再重定向（应已是最终地址）
                    timeout=60.0
            ) as resp:
                if resp.status_code != 200:
                    error_content = await resp.aread()
                    error_detail = error_content.decode('utf-8', errors='ignore')[:500]  # 截断防日志爆炸
                    logger.error(
                        f"❌ [BLOB代理] CDN 返回非 200 状态码 → "
                        f"Status: {resp.status_code} | URL: {url} | 响应片段: {error_detail}"
                    )
                    raise RuntimeError(f"CDN 返回错误状态码: {resp.status_code}")

                chunk_count = 0
                async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                    yield chunk
                    chunk_count += 1
                    if chunk_count % 100 == 0:  # 每 6.4MB 打一条 debug 日志
                        logger.debug(f"📦 [BLOB代理] 已传输 {chunk_count * 64} KB 数据")

        except Exception as e:
            logger.exception(f"💥 [BLOB代理] 流式传输失败 → URL: {url} | 错误: {e}")
            raise


# ======================
# 认证处理：拦截 401 并重写 WWW-Authenticate 中的 realm
# ======================
async def handle_401_and_cache_realm(
        upstream_resp: httpx.Response,
        upstream_host: str,
        original_request: Request
) -> Response:
    """
    处理来自上游注册表的 401 响应：
    1. 提取原始 realm
    2. 缓存到 REALM_CACHE（按 upstream_host 索引）
    3. 将 realm 重写为本地 /auth/token 路径
    4. 返回修改后的 401 响应给客户端
    """
    www_auth = upstream_resp.headers.get("www-authenticate", "")
    match = re.search(r'realm="([^"]+)"', www_auth)
    if not match:
        logger.warning("⚠️ [认证] WWW-Authenticate 头中未找到 realm 字段 → 跳过重写")
        return Response(status_code=401, headers={"www-authenticate": www_auth})

    original_realm = match.group(1)
    if upstream_host not in REALM_CACHE:
        REALM_CACHE[upstream_host] = original_realm
        logger.info(f"🔑 [认证] 首次缓存 upstream host '{upstream_host}' 的 realm: {original_realm}")

    # 获取当前代理域名（用于构造新的 realm）
    current_host = original_request.headers.get("host", "").split(":")[0]
    new_realm = f"https://{current_host}/auth/token"

    # 替换原始 realm 为本地 token 接口
    new_www_auth = www_auth.replace(original_realm, new_realm)
    logger.info(f"🔄 [认证] 成功重写 realm → 原始: {original_realm} → 新: {new_realm}")

    return Response(status_code=401, headers={"www-authenticate": new_www_auth})


# ======================
# 请求头处理：合并重复头 + 设置 Host
# ======================
async def handle_headers(request_headers: Headers) -> dict[str, str]:
    """
    将 Starlette 的 Headers 转换为标准 dict，并：
    - 合并重复的 header（如多个 Cookie）→ 用逗号连接（符合 RFC）
    - 强制设置 Host 头为目标 upstream 的主机名
    - 所有 header key 转为小写（HTTP 规范不区分大小写）
    """
    header_dict: dict[str, str] = {}

    for key, value in request_headers.raw:
        key_str = key.decode("latin-1").lower()
        val_str = value.decode("latin-1")
        if key_str == "host" or key_str == "content-encoding":
            # 去除host让请求自动添加
            # 去除content-encoding避免客户端二次解压，httpx底层在收到gzip等压缩头后会自动解压内容
            continue
        elif key_str in header_dict:
            header_dict[key_str] = f"{header_dict[key_str]},{val_str}"
        else:
            header_dict[key_str] = val_str
    return header_dict


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

    original_realm = REALM_CACHE.get(upstream_host)
    if not original_realm:
        logger.error(
            f"❓ [认证] realm 未就绪 → upstream_host: '{upstream_host}'。"
            "请先发起一次 /v2/ 请求以触发 401 并缓存 realm"
        )
        return Response(status_code=400, content="Realm 未就绪，请重试")

    # 保留原始 query 参数（如 ?service=registry.docker.io&scope=...）
    query = str(request.url.query)
    target_url = original_realm
    if query:
        separator = "&" if "?" in original_realm else "?"
        target_url += separator + query

    logger.info(f"🔐 [认证] 代理请求至上游认证服务 → {target_url}")

    async with httpx.AsyncClient() as client:
        try:
            headers = await handle_headers(request.headers)
            resp = await client.get(target_url, headers=headers, timeout=15.0)

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
async def proxy(path: str, request: Request):
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
    proxy_domain = request.headers.get("host", "")
    full_path = f"/v2/{path}"

    if proxy_domain not in settings.upstreams:
        logger.warning(f"🌐 [代理] 收到未知域名请求 → Host: {proxy_domain}")
        return Response(status_code=400, content="未知的注册表域名")

    upstream_base_url = settings.upstreams[proxy_domain]
    target_url = httpx.URL(upstream_base_url).join(full_path)
    upstream_host = target_url.host

    headers = await handle_headers(request.headers)
    logger.info(f"➡️ [代理] {request.method} {full_path} → {target_url}")

    async with httpx.AsyncClient() as client:
        try:
            upstream_resp = await client.request(
                method=request.method,
                url=target_url,
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
                return await handle_401_and_cache_realm(upstream_resp, upstream_host, request)

            # === 情况2: 3xx 重定向 ===
            if upstream_resp.status_code in (301, 302, 303, 307, 308):
                location = upstream_resp.headers.get("location")
                if not location:
                    logger.error("🔗 [代理] 3xx 响应缺少 Location 头 → 返回原响应")
                    return Response(status_code=upstream_resp.status_code, headers=dict(upstream_resp.headers))

                # 解析绝对 URL（处理相对重定向）
                resolved_location = urljoin(str(target_url), location)
                logger.info(f"🔗 [代理] 原始重定向: {location} → 解析后: {resolved_location}")

                # 判断是否为 blob 请求（关键！避免客户端直连 CDN）
                if "/blobs/" in full_path:
                    logger.info("📦 [代理] 检测到 blob 重定向 → 启动流式代理")
                    return StreamingResponse(
                        _stream_blob(resolved_location, headers),
                        status_code=200,
                        media_type="application/octet-stream"
                    )
                else:
                    # Manifest 或 tag 列表等 → 代取内容，隐藏重定向
                    logger.info("🔄 [代理] 拦截非-blob 重定向 → 代取内容并返回 200")
                    redirect_url = httpx.URL(resolved_location)
                    redirect_host = redirect_url.host

                    cdn_headers = {
                        "Host": redirect_host,
                        "User-Agent": headers.get("user-agent", "registry-proxy/0.0.1"),
                    }

                    async with httpx.AsyncClient() as cdn_client:
                        try:
                            cdn_resp = await cdn_client.get(
                                resolved_location,
                                headers=cdn_headers,
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
            resp_headers = await handle_headers(upstream_resp.headers)

            logger.debug(f"📡 [代理] 上游响应 → Status: {upstream_resp.status_code}")
            return Response(
                content=upstream_resp.content,
                status_code=upstream_resp.status_code,
                headers=resp_headers
            )

        except Exception as e:
            logger.exception(f"🔥 [代理] 请求上游失败 → Target: {target_url}")
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
