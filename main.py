# -*- coding: utf-8 -*-
"""
@FileName    : main.py
@Author      : jiaxin
@Date        : 2026/1/10
@Time        : 17:31
@Description :
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
# 加载配置 & 初始化日志
# ======================
settings = Settings()
logger = setup_logging(settings)  # ← 初始化日志

# 全局变量
REALM_CACHE: dict[str, str] = {}
app = FastAPI()


# ======================
# 工具：流式传输 blob
# ======================
async def _stream_blob(url: str, original_headers: dict) -> AsyncGenerator[bytes, None]:
    parsed_url = urlparse(url)
    host = parsed_url.hostname
    if not host:
        raise ValueError("无效的重定向 URL：缺少主机名")

    cdn_headers = {
        "Host": host,
        "User-Agent": original_headers.get("user-agent"),
    }

    logger.info(f"📥 [BLOB代理] 正在通过代理获取资源：{url} （Host: {host}）")

    async with httpx.AsyncClient() as client:
        try:
            async with client.stream(
                    method="GET",
                    url=url,
                    headers=cdn_headers,
                    follow_redirects=False,
                    timeout=60.0
            ) as resp:
                if resp.status_code != 200:
                    error_content = await resp.aread()
                    logger.error(
                        f"❌ [BLOB代理] CDN 返回非 200 状态码：{resp.status_code}，"
                        f"URL: {url}，响应内容：{error_content.decode('utf-8', errors='ignore')}"
                    )
                    raise RuntimeError(f"从 CDN 获取 blob 失败：{resp.status_code}")

                async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                    yield chunk

        except Exception as e:
            logger.exception(f"💥 [BLOB代理] 从 {url} 流式传输 blob 时发生错误：{e}")
            raise


# ======================
# 处理 401 认证
# ======================
async def handle_401_and_cache_realm(
        upstream_resp: httpx.Response,
        upstream_host: str,
        original_request: Request
) -> Response:
    www_auth = upstream_resp.headers.get("www-authenticate", "")
    match = re.search(r'realm="([^"]+)"', www_auth)
    if not match:
        logger.warning("⚠️ [认证] WWW-Authenticate 头中缺少 realm 字段")
        return Response(status_code=401, headers={"www-authenticate": www_auth})

    original_realm = match.group(1)
    if upstream_host not in REALM_CACHE:
        REALM_CACHE[upstream_host] = original_realm
        logger.info(f"🔑 [认证] 已缓存上游主机 {upstream_host} 的 realm：{original_realm}")

    current_host = original_request.headers.get("host", "").split(":")[0]
    new_realm = f"https://{current_host}/auth/token"
    new_www_auth = www_auth.replace(original_realm, new_realm)
    logger.info(f"🔄 [认证] 已重写 realm 为：{new_realm}")
    return Response(status_code=401, headers={"www-authenticate": new_www_auth})


async def handle_request_headers(request_headers: Headers, host: str) -> dict[str, str]:
    """
    处理请求头：
      - 替换 Host；
      - 合并重复的 header 字段（用逗号连接）；
      - 返回标准 dict[str, str] 格式的 headers。
    """
    header: dict[str, str] = {}

    # 遍历所有原始头（包括重复键）
    for key, value in request_headers.raw:
        key_str = key.decode("latin-1").lower()  # HTTP 头不区分大小写，通常转小写处理
        val_str = value.decode("latin-1")
        if key_str not in header:
            header[key_str] = val_str
        else:
            header[key_str] = f"{header[key_str]},{val_str}"
    # 设置新的 Host 头
    header["host"] = host
    return header



# ======================
# 健康检查
# ======================
@app.get("/healthz", response_model=HealthCheckResponse)
async def health_check():
    logger.debug("🩺 [健康检查] 收到健康探测请求")
    return HealthCheckResponse(status="ok", message="registry-proxy is running", version="0.0.1")


# ======================
# 认证路由
# ======================
@app.get("/auth/token")
async def auth_token(request: Request):
    # 👇 从 Host 头获取当前代理域名
    host_header = request.headers.get("host", "")
    proxy_domain = host_header.split(":")[0]

    # 根据 proxy_domain 找到对应的 upstream host（用于查 REALM_CACHE）
    if proxy_domain not in settings.upstreams:
        logger.error(f"❓ [认证] 未知的代理域名：{proxy_domain}")
        return Response(status_code=400, content="未知的registry-proxy域名")

    # 获取 upstream_base 的主机名（例如 registry-1.docker.io）
    upstream_base = settings.upstreams[proxy_domain]
    upstream_host = httpx.URL(upstream_base).host

    original_realm = REALM_CACHE.get(upstream_host)
    if not original_realm:
        logger.error(f"❓ [认证] 尚未缓存 upstream_host '{upstream_host}' 的 realm（请先触发一次 /v2/ 请求）")
        return Response(status_code=400, content="Realm 未就绪，请重试")

    # 构造目标 URL：保留原始 query（service, scope 等）
    query = str(request.url.query)
    target_url = original_realm
    if query:
        target_url += ("&" if "?" in original_realm else "?") + query

    logger.info(f"🔐 [认证] 正在代理请求至：{target_url}")

    async with httpx.AsyncClient() as client:
        try:
            headers = await handle_request_headers(request.headers, upstream_host)
            resp = await client.get(
                target_url,
                headers=headers,
            )
            logger.info(f"✅ [认证] 上游服务返回状态码：{resp.status_code}")
            resp.headers.pop("content-encoding", None)  # 移除 gzip 压缩头标识
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=dict(resp.headers)
            )
        except Exception as e:
            logger.exception("🚨 [认证] 代理请求失败")
            return Response(status_code=502, content="认证服务不可达")


# ======================
# 主代理路由
# ======================
@app.api_route("/v2/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(path: str, request: Request):
    host_header = request.headers.get("host", "")
    domain = host_header.split(":")[0]
    full_path = f"/v2/{path}"

    if domain not in settings.upstreams:
        logger.warning(f"🌐 [代理] 未知的请求域名：{domain}")
        return Response(status_code=400, content="未知的注册表域名")

    upstream_base = settings.upstreams[domain]
    target_url = httpx.URL(upstream_base).join(full_path)
    upstream_host = target_url.host

    headers = await handle_request_headers(request.headers, upstream_host)

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

            # 处理 401 认证
            if (
                upstream_resp.status_code == 401
                and upstream_resp.headers.get("www-authenticate", "").lower().startswith("bearer ")
            ):
                logger.info("🛡️ [代理] 拦截到 401 认证请求，正在重写 realm")
                return await handle_401_and_cache_realm(upstream_resp, upstream_host, request)

            # 处理 3xx 重定向
            if upstream_resp.status_code in (301, 302, 303, 307, 308):
                logger.exception(f"响应头 {upstream_resp.headers}")
                location = upstream_resp.headers.get("location")
                location = urljoin(str(target_url), location)
                logger.info(f"🔗 [代理] 解析后的重定向目标: {location}")
                if location:
                    if "/blobs/" in full_path:
                        # Blob 重定向：流式代理
                        logger.info(f"📦 [代理] 检测到 blob 重定向 → 正通过代理拉取：{location}")
                        return StreamingResponse(
                            _stream_blob(location, headers),
                            status_code=200,
                            media_type="application/octet-stream"
                        )
                    else:
                        # Manifest 或其他重定向：由代理代取，返回 200
                        logger.info(f"🔄 [代理] 拦截非-blob 重定向 → 代理拉取内容：{location}")
                        redirect_url = httpx.URL(location)
                        redirect_host = redirect_url.host
                        cdn_headers = {
                            "Host": redirect_host,
                            "User-Agent": headers.get("user-agent", ""),
                        }

                        async with httpx.AsyncClient() as cdn_client:
                            try:
                                cdn_resp = await cdn_client.get(
                                    location,
                                    headers=cdn_headers,
                                    timeout=30.0
                                )
                                # 构造干净的响应头
                                resp_headers = dict(cdn_resp.headers)

                                # 返回实际内容，状态码改为 200
                                return Response(
                                    content=cdn_resp.content,
                                    status_code=200,
                                    headers=resp_headers
                                )
                            except Exception as e:
                                logger.exception(f"💥 [代理] 拉取重定向目标失败：{location} | 错误: {e}")
                                return Response(status_code=502, content="Failed to fetch redirected resource")

            # 普通响应（非 401、非 3xx）
            resp_headers = dict(upstream_resp.headers)
            resp_headers.pop("content-encoding", None)  # 移除 gzip 压缩头标识

            logger.debug(f"📡 [代理] 上游响应状态码：{upstream_resp.status_code}")
            return Response(
                content=upstream_resp.content,
                status_code=upstream_resp.status_code,
                headers=resp_headers
            )

        except Exception as e:
            logger.exception(f"🔥 [代理] 代理请求到 {target_url} 时失败")
            return Response(status_code=502, content="网关错误（Bad Gateway）")


# ======================
# 启动入口
# ======================
if __name__ == "__main__":
    import uvicorn

    logger.info("📚 已加载的上游注册表映射：")
    for domain, url in settings.upstreams.items():
        logger.info(f"  🌍 {domain} → {url}")

    ssl_args = {}
    if settings.https.enable:
        if not settings.https.cert or not settings.https.key:
            raise ValueError("HTTPS 已启用，但配置中缺少 'cert' 或 'key'")
        ssl_args = {
            "ssl_certfile": settings.https.cert,
            "ssl_keyfile": settings.https.key
        }
        logger.info(f"🔒 正在启动 HTTPS 代理：https://{settings.listen.host}:{settings.listen.port}")
    else:
        logger.info(f"🔌 正在启动 HTTP 代理：http://{settings.listen.host}:{settings.listen.port}")

    uvicorn.run(
        app,
        host=settings.listen.host,
        port=settings.listen.port,
        reload=False,
        **ssl_args
    )