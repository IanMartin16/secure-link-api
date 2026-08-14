from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Secure_Link API"
    app_version: str = "1.0.0"
    APP_VERSION: str = "2.0.0"
    app_env: str = "development"
    ENVIRONMENT: str = "development"
    log_level: str = "INFO"
    api_key: str = "change-me-in-production"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()