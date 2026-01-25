# -*- coding: utf-8 -*-
"""
@FileName    : logger.py
@Author      : jiaxin
@Date        : 2026/1/10
@Time        : 17:29
@Description :
"""
import logging
from .settings import Settings


def setup_logging(settings: Settings):
    """根据配置初始化全局日志"""
    level = getattr(logging, settings.log_level.upper())
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        force=True  # 覆盖可能已存在的 root logger 配置
    )
    logger = logging.getLogger("registry-proxy")
    logger.info(f"Logging initialized at level: {logging.getLevelName(level)}")
    return logger


def get_logger():
    """获取统一命名的日志实例"""
    return logging.getLogger("registry-proxy")
