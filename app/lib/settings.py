# -*- coding: utf-8 -*-
"""
@FileName    : settings.py
@Author      : jiaxin
@Date        : 2026/1/10
@Time        : 17:30
@Description :
"""
from pathlib import Path
from typing import Any, Dict, Optional
from pydantic import BaseModel, model_validator, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_settings.sources import PydanticBaseSettingsSource
from functools import lru_cache
import yaml


class ListenConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000

class DocsConfig(BaseModel):
    enabled: bool = False

class HTTPSConfig(BaseModel):
    enabled: bool = False
    cert: Optional[str] = None
    key: Optional[str] = None

    @model_validator(mode='after')
    def validate_cert_and_key_if_enabled(self):
        if self.enabled:
            if not self.cert or not self.key:
                raise ValueError("'https.cert' and 'https.key' are required when 'https.enabled' is true")
            cert_path = Path(self.cert)
            key_path = Path(self.key)
            if not cert_path.exists():
                raise ValueError(f"Certificate file not found: {self.cert}")
            if not key_path.exists():
                raise ValueError(f"Private key file not found: {self.key}")
        return self


class Settings(BaseSettings):
    listen: ListenConfig = Field(default_factory=ListenConfig)
    docs: DocsConfig = Field(default_factory=DocsConfig)
    https: HTTPSConfig = Field(default_factory=HTTPSConfig)
    upstreams: Dict[str, str] = Field(default_factory=..., description="Upstream registry mappings from config.yaml")
    log_level: str = "INFO"

    @classmethod
    def settings_customise_sources(
            cls,
            settings_cls,
            init_settings,
            env_settings,
            dotenv_settings,
            file_secret_settings,
    ):
        class YamlSettingsSource(PydanticBaseSettingsSource):
            def get_field_value(self, field_name: str, field: Any) -> tuple[Any, str, bool]:
                return None, "", False

            def __call__(self) -> Dict[str, Any]:
                # 这里可以硬编码路径，或从环境变量读取 config_file
                config_file = "config.yaml"  # 或从 env 获取
                if Path(config_file).exists():
                    with open(config_file, "r", encoding="utf-8") as f:
                        return yaml.safe_load(f) or {}
                return {}

        return (
            init_settings,
            env_settings,
            dotenv_settings,
            file_secret_settings,
            YamlSettingsSource(settings_cls),
        )

    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="forbid",  # 禁止未定义字段
    )

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
