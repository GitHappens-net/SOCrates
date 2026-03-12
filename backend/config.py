import os
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
