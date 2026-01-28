# -*- coding: utf-8 -*-
"""
@FileName    : utils.py
@Author      : jiaxin
@Date        : 2026/1/20
@Time        : 00:22
@Description :
工具函数模块，包含：
- 请求头处理
- 认证 realm 重写与缓存
- 流式下载代理
- 流式上传代理
"""

from lib.logger import get_logger
from typing import AsyncGenerator
import httpx
from fastapi import Request, Response
from starlette.datastructures import Headers
import re

logger = get_logger()

# 全局缓存：存储各 upstream host 对应的原始认证 realm
REALM_CACHE: dict[str, str] = {}


# ======================
# 请求头处理：合并重复头 + 设置 Host
# ======================
async def handle_headers(request_headers: Headers) -> dict[str, str]:
    """
    将 Starlette 的 Headers 转换为标准 dict，并：
    - 合并重复的 header（如多个 Cookie）→ 用逗号连接（符合 RFC）
    - 移除 'host' 和 'content-encoding' 头（由底层自动处理）
    - 所有 header key 转为小写（HTTP 规范不区分大小写）

    注意：移除 content-encoding 是为了避免 FastAPI 二次压缩已解压内容。
    """
    header_dict: dict[str, str] = {}

    for key, value in request_headers.raw:
        key_str = key.decode("latin-1").lower()
        val_str = value.decode("latin-1")

        # 忽略 Host 和 Content-Encoding（httpx 自动设置 Host；避免重复解压）
        if key_str in ("host", "content-encoding"):
            continue

        if key_str in header_dict:
            header_dict[key_str] = f"{header_dict[key_str]},{val_str}"
        else:
            header_dict[key_str] = val_str

    logger.debug(f"🔧 [Headers] 已处理请求头 → 共 {len(header_dict)} 项")
    return header_dict


# ======================
# 认证处理：拦截 401 并重写 WWW-Authenticate 中的 realm
# ======================
async def handle_401_and_cache_realm(
        upstream_resp: httpx.Response,
        request: Request
) -> Response:
    """
    处理来自上游注册表的 401 响应：
    1. 提取原始 realm
    2. 缓存到 REALM_CACHE（按 upstream host 索引）
    3. 将 realm 重写为本地 /auth/token 路径
    4. 返回修改后的 401 响应给客户端

    若未匹配到 realm，则原样返回 401。
    """
    www_auth = upstream_resp.headers.get("www-authenticate", "")
    match = re.search(r'realm="([^"]+)"', www_auth)
    if not match:
        logger.warning("⚠️ [认证] WWW-Authenticate 头中未找到 realm 字段 → 跳过重写")
        return Response(status_code=401, headers={"www-authenticate": www_auth})

    upstream_realm = match.group(1)
    upstream_host = upstream_resp.url.host

    # 缓存 realm（仅首次）
    if upstream_host not in REALM_CACHE:
        REALM_CACHE[upstream_host] = upstream_realm
        logger.info(f"🔑 [认证] 首次缓存 upstream host '{upstream_host}' 的 realm: {upstream_realm}")
    else:
        logger.debug(f"🔁 [认证] 使用已缓存的 realm for host '{upstream_host}'")

    # 构造新的本地 token 接口地址（使用当前请求的 Host）
    new_realm = f"https://{request.url.hostname}/auth/token"

    # 替换原始 realm
    new_www_auth = www_auth.replace(upstream_realm, new_realm)
    logger.info(f"🔄 [认证] 成功重写 realm → 原始: {upstream_realm} → 新: {new_realm}")

    return Response(status_code=401, headers={"www-authenticate": new_www_auth})


# ======================
# 工具函数：流式代理 Blob 内容（用于处理 CDN 重定向）
# ======================
async def stream_download(url: str) -> AsyncGenerator[bytes, None]:
    """
    从给定 URL 流式拉取二进制内容（如 layer/blob），并透传给客户端。

    特性：
    - 不跟随重定向（调用方应确保 url 是最终 CDN 地址）
    - 使用默认 User-Agent（避免被 CDN 拒绝）
    - 每传输 6.4MB 打一条 debug 日志（便于监控大文件传输）

    异常时抛出 RuntimeError，由上层捕获返回 5xx。
    """
    logger.info(f"📥 [BLOB代理] 开始流式拉取资源 → URL: {url}")

    async with httpx.AsyncClient() as client:
        try:
            async with client.stream(
                    method="GET",
                    url=url,
                    follow_redirects=False,
                    timeout=60.0
            ) as resp:
                if resp.status_code != 200:
                    error_content = await resp.aread()
                    error_detail = error_content.decode('utf-8', errors='ignore')[:500]
                    logger.error(
                        f"❌ [BLOB代理] CDN 返回非 200 状态码 → "
                        f"Status: {resp.status_code} | URL: {url} | 响应片段: {error_detail}"
                    )
                    raise RuntimeError(f"CDN 返回错误状态码: {resp.status_code}")

                chunk_count = 0
                async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                    yield chunk
                    chunk_count += 1
                    if chunk_count % 100 == 0:
                        logger.debug(f"📦 [BLOB代理] 已传输 {chunk_count * 64} KB 数据")

                logger.info(f"✅ [BLOB代理] 流式传输完成 → 总计 {chunk_count * 64} KB")

        except Exception as e:
            logger.exception(f"💥 [BLOB代理] 流式传输失败 → URL: {url} | 错误: {e}")
            raise


# ======================
# 工具函数：流式代理上传（用于处理分块上传 PATCH）
# ======================
async def stream_upload(
        url: str,
        headers: dict[str, str],
        request: Request
) -> httpx.Response:
    """
    流式转发客户端的 PATCH 上传请求到 upstream，避免将整个 body 加载进内存。

    适用于 Docker Registry 的 blob 分块上传（PATCH /v2/.../blobs/uploads/...）。
    """
    logger.info(f"📤 [UPLOAD代理] 开始流式上传 → URL: {url}")

    async def _body_stream():
        """生成器：逐块读取客户端上传内容"""
        async for chunk in request.stream():
            yield chunk

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.patch(
                url=url,
                headers=headers,
                content=_body_stream(),
                timeout=60.0  # 上传可能较慢
            )
            logger.info(f"✅ [UPLOAD代理] 上传完成 → 上游响应状态码: {resp.status_code}")
            return resp
        except Exception as e:
            logger.exception(f"💥 [UPLOAD代理] 流式上传失败 → URL: {url} | 错误: {e}")
            raise