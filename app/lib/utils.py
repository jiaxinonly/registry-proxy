# -*- coding: utf-8 -*-
"""
@FileName    : utils.py
@Author      : jiaxin
@Date        : 2026/1/20
@Time        : 00:22
@Description : 
"""
from app.lib.logger import get_logger
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
# 认证处理：拦截 401 并重写 WWW-Authenticate 中的 realm
# ======================
async def handle_401_and_cache_realm(
        upstream_resp: httpx.Response,
        request: Request
) -> Response:
    """
    处理来自上游注册表的 401 响应：
    1. 提取原始 realm
    2. 缓存到 REALM_CACHE
    3. 将 realm 重写为本地 /auth/token 路径
    4. 返回修改后的 401 响应给客户端
    """
    www_auth = upstream_resp.headers.get("www-authenticate", "")
    match = re.search(r'realm="([^"]+)"', www_auth)
    if not match:
        logger.warning("⚠️ [认证] WWW-Authenticate 头中未找到 realm 字段 → 跳过重写")
        return Response(status_code=401, headers={"www-authenticate": www_auth})

    upstream_realm = match.group(1)
    if upstream_resp.url.host not in REALM_CACHE:
        REALM_CACHE[upstream_resp.url.host] = upstream_realm
        logger.info(f"🔑 [认证] 首次缓存 upstream host '{upstream_resp.url.host}' 的 realm: {upstream_realm}")

    # 获取当前代理域名（用于构造新的 realm）
    new_realm = f"https://{request.url.hostname}/auth/token"

    # 替换原始 realm 为本地 token 接口
    new_www_auth = www_auth.replace(upstream_realm, new_realm)
    logger.info(f"🔄 [认证] 成功重写 realm → 原始: {upstream_realm} → 新: {new_realm}")

    return Response(status_code=401, headers={"www-authenticate": new_www_auth})


# ======================
# 工具函数：流式代理 Blob 内容（用于处理 CDN 重定向）
# ======================
async def stream_download(url: str) -> AsyncGenerator[bytes, None]:
    """
    从给定 URL 流式拉取二进制内容（如 layer/blob），并透传给客户端。

    注意：
    - 不跟随重定向（由调用方确保 url 是最终 CDN 地址）
    - 使用 Host 头欺骗以绕过 CDN 的 Host 校验
    """
    logger.info(f"📥 [BLOB代理] 开始流式拉取资源 → URL: {url}")

    async with httpx.AsyncClient() as client:
        try:
            async with client.stream(
                    method="GET",
                    url=url,
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
# 工具函数：流式代理上传（用于处理分块上传 PATCH）
# ======================
async def stream_upload(
        url: str,
        headers: dict,
        request: Request
) -> httpx.Response:
    """
    流式转发客户端的 PATCH 上传请求到 upstream，避免将整个 body 加载进内存。
    """
    logger.info(f"📤 [UPLOAD代理] 开始流式上传 → URL: {url}")

    async with httpx.AsyncClient() as client:
        try:
            # 使用 stream=True + aiter_bytes 转发 body
            async def _body_stream():
                async for chunk in request.stream():
                    yield chunk

            resp = await client.patch(
                url=url,
                headers=headers,
                content=_body_stream(),
                timeout=60.0  # 上传可能较慢，延长超时
            )
            return resp
        except Exception as e:
            logger.exception(f"💥 [UPLOAD代理] 流式上传失败 → URL: {url} | 错误: {e}")
            raise
