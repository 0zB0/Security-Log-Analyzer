import os

from pydantic import BaseModel
from dotenv import load_dotenv


load_dotenv()


class Settings(BaseModel):
    db_path: str = os.getenv("TRACEHAWK_DB_PATH", "tracehawk.db")
    web_dist_path: str = os.getenv("TRACEHAWK_WEB_DIST", "")
    allowed_auth_emails: str = os.getenv("ALLOWED_AUTH_EMAILS", "")
    auth_mode: str = os.getenv("TRACEHAWK_AUTH_MODE", "disabled")
    auth_admin_emails: str = os.getenv("TRACEHAWK_ADMIN_EMAILS", "")
    auth_analyst_emails: str = os.getenv("TRACEHAWK_ANALYST_EMAILS", "")
    auth_viewer_emails: str = os.getenv("TRACEHAWK_VIEWER_EMAILS", "")
    build_commit: str = os.getenv("TRACEHAWK_BUILD_COMMIT", "local")
    runtime_mode: str = os.getenv("TRACEHAWK_RUNTIME_MODE", "local")
    llm_provider: str = os.getenv("TRACEHAWK_LLM_PROVIDER", "ollama")
    ollama_url: str = os.getenv("TRACEHAWK_OLLAMA_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("TRACEHAWK_OLLAMA_MODEL", "gpt-oss:20b")
    ollama_timeout_seconds: float = float(os.getenv("TRACEHAWK_OLLAMA_TIMEOUT_SECONDS", "45"))
    llm_max_evidence_lines: int = int(os.getenv("TRACEHAWK_LLM_MAX_EVIDENCE_LINES", "20"))
    llm_max_evidence_chars: int = int(os.getenv("TRACEHAWK_LLM_MAX_EVIDENCE_CHARS", "4000"))
    max_upload_bytes: int = int(os.getenv("MAX_UPLOAD_BYTES", "2000000"))
    max_case_files: int = int(os.getenv("MAX_CASE_FILES", "8"))
    max_case_total_bytes: int = int(os.getenv("MAX_CASE_TOTAL_BYTES", "8000000"))
    max_upload_lines: int = int(os.getenv("MAX_UPLOAD_LINES", "100000"))
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
    allowed_upload_extensions: str = os.getenv(
        "ALLOWED_UPLOAD_EXTENSIONS",
        ".log,.txt,.csv,.json,.jsonl,.xml",
    )


settings = Settings()
