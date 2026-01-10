# -*- coding: utf-8 -*-
"""
@FileName    : schemas.py
@Author      : jiaxin
@Date        : 2026/1/10
@Time        : 17:29
@Description :
"""
from pydantic import BaseModel
from typing import Optional


class HealthCheckResponse(BaseModel):
    status: str
    message: str
    version: Optional[str] = None
