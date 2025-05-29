from pydantic_settings import BaseSettings  # Değişen import
from pydantic import Field
import os
from pathlib import Path

class Settings(BaseSettings):
    APP_NAME: str = "Cloud Maskaleme Security Suite"
    DATABASE_URL: str = Field(default="sqlite:///./security.db", env="DATABASE_URL")
    BLOCKCHAIN_DIFFICULTY: int = Field(default=4, env="BLOCKCHAIN_DIFFICULTY")
    THREAT_INTEL_API_KEY: str = Field(default="", env="THREAT_INTEL_API_KEY")
    
    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'

settings = Settings()