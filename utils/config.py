"""Environment-backed application configuration."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Validated settings loaded from environment variables or `.env`."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="CYBERSHIELD_",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "CyberShield AI"
    app_version: str = "0.1.0"
    environment: str = "development"
    log_level: str = "INFO"
    enable_api_docs: bool = True
    max_contract_bytes: int = Field(default=1_000_000, gt=0)
    template_directory: Path = Field(default=PROJECT_ROOT / "templates")
    static_directory: Path = Field(default=PROJECT_ROOT / "static")


@lru_cache
def get_settings() -> Settings:
    """Return one immutable-by-convention settings instance per process."""
    return Settings()
