"""Configuration management for the email investigation tool."""

import os
from dataclasses import dataclass
from typing import Optional
from dotenv import load_dotenv

@dataclass
class SMTPConfig:
    """SMTP server configuration."""
    host: str
    port: int
    use_tls: bool
    username: str
    password: str

@dataclass
class IMAPConfig:
    """IMAP server configuration."""
    host: str
    port: int
    use_ssl: bool
    username: str
    password: str

@dataclass
class AppConfig:
    """Application configuration."""
    log_level: str
    max_attachment_size: int
    default_theme: str
    smtp: SMTPConfig
    imap: IMAPConfig

def load_config() -> AppConfig:
    """Load configuration from .env file."""
    load_dotenv()
    
    # SMTP Configuration
    smtp_config = SMTPConfig(
        host=os.getenv("SMTP_HOST", "smtp.gmail.com"),
        port=int(os.getenv("SMTP_PORT", "587")),
        use_tls=os.getenv("SMTP_USE_TLS", "true").lower() == "true",
        username=os.getenv("SMTP_USERNAME", ""),
        password=os.getenv("SMTP_PASSWORD", "")
    )
    
    # IMAP Configuration
    imap_config = IMAPConfig(
        host=os.getenv("IMAP_HOST", "imap.gmail.com"),
        port=int(os.getenv("IMAP_PORT", "993")),
        use_ssl=os.getenv("IMAP_USE_SSL", "true").lower() == "true",
        username=os.getenv("IMAP_USERNAME", ""),
        password=os.getenv("IMAP_PASSWORD", "")
    )
    
    # Application Configuration
    return AppConfig(
        log_level=os.getenv("LOG_LEVEL", "DEBUG"),
        max_attachment_size=int(os.getenv("MAX_ATTACHMENT_SIZE", "25")),
        default_theme=os.getenv("DEFAULT_THEME", "dark"),
        smtp=smtp_config,
        imap=imap_config
    )

def validate_config(config: AppConfig) -> list[str]:
    """Validate configuration and return list of errors."""
    errors = []
    
    if not config.smtp.host:
        errors.append("SMTP_HOST is required")
    if not config.smtp.username:
        errors.append("SMTP_USERNAME is required")
    if not config.smtp.password:
        errors.append("SMTP_PASSWORD is required")
    
    if not config.imap.host:
        errors.append("IMAP_HOST is required")
    if not config.imap.username:
        errors.append("IMAP_USERNAME is required")
    if not config.imap.password:
        errors.append("IMAP_PASSWORD is required")
    
    if config.max_attachment_size < 1:
        errors.append("MAX_ATTACHMENT_SIZE must be at least 1MB")
    
    return errors