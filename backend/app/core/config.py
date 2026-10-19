from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    PROJECT_NAME: str = "ThreatLens"
    PROJECT_TAGLINE: str = "See Beyond the Threat"
    API_V1_STR: str = "/api"
    DATABASE_URL: str = f"sqlite:///{BASE_DIR}/threatlens.db"
    
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ]
    
    # Optional external threat intelligence API keys
    VIRUSTOTAL_API_KEY: str = ""
    ALIENVAULT_OTX_API_KEY: str = ""
    
    # Storage and artifacts
    MODEL_DIR: str = str(BASE_DIR / "app" / "ml" / "artifacts")
    DATASET_DIR: str = str(BASE_DIR.parent / "datasets")
    
    # Processing limits
    MAX_TEXT_SIZE_BYTES: int = 1_000_000  # 1 MB max input text
    MAX_FILE_SIZE_BYTES: int = 10_000_000  # 10 MB max document upload

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
