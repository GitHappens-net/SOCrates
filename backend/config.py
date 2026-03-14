import os
import json
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(Path(__file__).resolve().parent / ".env")

# OpenAI configuration
OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL_AGENT: str = os.getenv("OPENAI_MODEL_AGENT", "gpt-4.1")
OPENAI_MODEL_PARSER: str = os.getenv("OPENAI_MODEL_PARSER", "gpt-4.1")
OPENAI_MODEL_REASONING: str = os.getenv("OPENAI_MODEL_REASONING", "gpt-5.1")

# Initialize OpenAI client
OPENAI_CLIENT: OpenAI | None = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# Syslog configuration
SYSLOG_HOST: str = os.getenv("SYSLOG_HOST", "0.0.0.0")
SYSLOG_PORT: int = int(os.getenv("SYSLOG_PORT", "514"))

# API configuration
API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
API_PORT: int = int(os.getenv("API_PORT", "5000"))

# SOAR / FortiGate configuration
FORTIGATE_API_TOKEN: str | None = os.getenv("FORTIGATE_API_TOKEN")
FORTIGATE_TOKENS_JSON: dict[str, str] = {}
_FG_TOKENS_RAW = os.getenv("FORTIGATE_TOKENS_JSON", "")
if _FG_TOKENS_RAW:
    try:
        parsed = json.loads(_FG_TOKENS_RAW)
        if isinstance(parsed, dict):
            FORTIGATE_TOKENS_JSON = {str(k): str(v) for k, v in parsed.items()} 
    except json.JSONDecodeError:
        FORTIGATE_TOKENS_JSON = {}

FORTIGATE_VERIFY_SSL: bool = os.getenv("FORTIGATE_VERIFY_SSL", "false").lower() in ("1", "true", "yes")
FORTIGATE_TIMEOUT_SECONDS: int = int(os.getenv("FORTIGATE_TIMEOUT_SECONDS", "10"))

# SOAR / Palo Alto configuration
PALOALTO_API_KEY: str | None = os.getenv("PALOALTO_API_KEY")
PALOALTO_TOKENS_JSON: dict[str, str] = {}
_PA_TOKENS_RAW = os.getenv("PALOALTO_TOKENS_JSON", "")
if _PA_TOKENS_RAW:
    try:
        parsed = json.loads(_PA_TOKENS_RAW)
        if isinstance(parsed, dict):
            PALOALTO_TOKENS_JSON = {str(k): str(v) for k, v in parsed.items()} 
    except json.JSONDecodeError:
        PALOALTO_TOKENS_JSON = {}

PALOALTO_VERIFY_SSL: bool = os.getenv("PALOALTO_VERIFY_SSL", "false").lower() in ("1", "true", "yes")
PALOALTO_TIMEOUT_SECONDS: int = int(os.getenv("PALOALTO_TIMEOUT_SECONDS", "10"))
SOAR_AUTO_RESPONSE_MIN_SEVERITY: str = os.getenv("SOAR_AUTO_RESPONSE_MIN_SEVERITY", "high").lower()
SOAR_CHAT_REQUIRE_CONFIRMATION: bool = os.getenv("SOAR_CHAT_REQUIRE_CONFIRMATION", "true").lower() in ("1", "true", "yes")
SOAR_AUTO_RESPONSE_ENABLED: bool = os.getenv("SOAR_AUTO_RESPONSE_ENABLED", "false").lower() in ("1", "true", "yes")
