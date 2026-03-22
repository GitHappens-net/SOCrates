import os
import json
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

# Ensure these are importable from other modules
__all__ = [
    "OPENAI_CLIENT",
    "OPENAI_MODEL_AGENT",
    "OPENAI_MODEL_REASONING",
    "OPENAI_MODEL_PARSER",
    # Add other config symbols as needed
]

load_dotenv(Path(__file__).resolve().parent / ".env")

# OpenAI configuration
OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY")
OPENAI_BASE_URL: str | None = os.getenv("OPENAI_BASE_URL")
OPENAI_MODEL_AGENT: str | None = os.getenv("OPENAI_MODEL_AGENT")
OPENAI_MODEL_PARSER: str | None = os.getenv("OPENAI_MODEL_PARSER")
OPENAI_MODEL_REASONING: str | None = os.getenv("OPENAI_MODEL_REASONING")

# Initialize OpenAI client for Groq
OPENAI_CLIENT: OpenAI | None = OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL) if OPENAI_API_KEY else None

# Syslog configuration
SYSLOG_HOST: str | None = os.getenv("SYSLOG_HOST")
_SYSLOG_PORT_ENV = os.getenv("SYSLOG_PORT")
SYSLOG_PORT: int | None = int(_SYSLOG_PORT_ENV) if _SYSLOG_PORT_ENV else None

# API configuration
API_HOST: str | None = os.getenv("API_HOST")
_API_PORT_ENV = os.getenv("API_PORT")
API_PORT: int | None = int(_API_PORT_ENV) if _API_PORT_ENV else None

# SOAR / FortiGate configuration
FORTIGATE_IP: str | None = os.getenv("FORTIGATE_IP")
FORTIGATE_API_TOKEN: str | None = os.getenv("FORTIGATE_API_TOKEN")
FORTIGATE_TOKENS_JSON: dict[str, str] = {}
_FG_TOKENS_RAW = os.getenv("FORTIGATE_TOKENS_JSON")
if _FG_TOKENS_RAW:
    try:
        parsed = json.loads(_FG_TOKENS_RAW)
        if isinstance(parsed, dict):
            FORTIGATE_TOKENS_JSON = {str(k): str(v) for k, v in parsed.items()} 
    except json.JSONDecodeError:
        FORTIGATE_TOKENS_JSON = {}

_FG_VERIFY_SSL_ENV = os.getenv("FORTIGATE_VERIFY_SSL")
FORTIGATE_VERIFY_SSL: bool = _FG_VERIFY_SSL_ENV.lower() in ("1", "true", "yes") if _FG_VERIFY_SSL_ENV else False
_FG_TIMEOUT_ENV = os.getenv("FORTIGATE_TIMEOUT_SECONDS")
FORTIGATE_TIMEOUT_SECONDS: int | None = int(_FG_TIMEOUT_ENV) if _FG_TIMEOUT_ENV else None

# SOAR / Windows configuration
WINDOWS_IP: str | None = os.getenv("WINDOWS_IP")
WINDOWS_USERNAME: str | None = os.getenv("WINDOWS_USERNAME")
WINDOWS_PASSWORD: str | None = os.getenv("WINDOWS_PASSWORD")

# SOAR / Palo Alto configuration
PALOALTO_API_KEY: str | None = os.getenv("PALOALTO_API_KEY")
PALOALTO_TOKENS_JSON: dict[str, str] = {}
_PA_TOKENS_RAW = os.getenv("PALOALTO_TOKENS_JSON")
if _PA_TOKENS_RAW:
    try:
        parsed = json.loads(_PA_TOKENS_RAW)
        if isinstance(parsed, dict):
            PALOALTO_TOKENS_JSON = {str(k): str(v) for k, v in parsed.items()}
    except json.JSONDecodeError:
        PALOALTO_TOKENS_JSON = {}

_PA_VERIFY_SSL_ENV = os.getenv("PALOALTO_VERIFY_SSL")
PALOALTO_VERIFY_SSL: bool = _PA_VERIFY_SSL_ENV.lower() in ("1", "true", "yes") if _PA_VERIFY_SSL_ENV else False
_PA_TIMEOUT_ENV = os.getenv("PALOALTO_TIMEOUT_SECONDS")
PALOALTO_TIMEOUT_SECONDS: int | None = int(_PA_TIMEOUT_ENV) if _PA_TIMEOUT_ENV else None

_SOAR_SEVERITY_ENV = os.getenv("SOAR_AUTO_RESPONSE_MIN_SEVERITY")
SOAR_AUTO_RESPONSE_MIN_SEVERITY: str | None = _SOAR_SEVERITY_ENV.lower() if _SOAR_SEVERITY_ENV else None

_SOAR_CONFIRM_ENV = os.getenv("SOAR_CHAT_REQUIRE_CONFIRMATION")
SOAR_CHAT_REQUIRE_CONFIRMATION: bool = _SOAR_CONFIRM_ENV.lower() in ("1", "true", "yes") if _SOAR_CONFIRM_ENV else False

_SOAR_AUTO_ENV = os.getenv("SOAR_AUTO_RESPONSE_ENABLED")
SOAR_AUTO_RESPONSE_ENABLED: bool = _SOAR_AUTO_ENV.lower() in ("1", "true", "yes") if _SOAR_AUTO_ENV else False
