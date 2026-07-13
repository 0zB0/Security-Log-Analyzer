import os

from pydantic import BaseModel, Field
from dotenv import load_dotenv


load_dotenv()


DEPLOYMENT_PROFILE_PRIVATE = "private"
DEPLOYMENT_PROFILE_PUBLIC_DEMO = "public_demo"
SUPPORTED_DEPLOYMENT_PROFILES = {
    DEPLOYMENT_PROFILE_PRIVATE,
    DEPLOYMENT_PROFILE_PUBLIC_DEMO,
}


class Settings(BaseModel):
    deployment_profile: str = os.getenv(
        "TRACEHAWK_DEPLOYMENT_PROFILE",
        DEPLOYMENT_PROFILE_PRIVATE,
    )
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
    public_demo_max_bytes: int = Field(
        default=int(os.getenv("PUBLIC_DEMO_MAX_BYTES", str(512 * 1024))),
        ge=1,
        le=512 * 1024,
    )
    public_demo_max_lines: int = Field(
        default=int(os.getenv("PUBLIC_DEMO_MAX_LINES", "20000")),
        ge=1,
        le=20_000,
    )
    public_demo_rate_limit_requests: int = Field(
        default=int(os.getenv("PUBLIC_DEMO_RATE_LIMIT_REQUESTS", "5")),
        ge=1,
        le=5,
    )
    public_demo_rate_limit_window_seconds: int = Field(
        default=int(os.getenv("PUBLIC_DEMO_RATE_LIMIT_WINDOW_SECONDS", "600")),
        ge=600,
        le=3_600,
    )
    public_demo_max_concurrency: int = Field(
        default=int(os.getenv("PUBLIC_DEMO_MAX_CONCURRENCY", "2")),
        ge=1,
        le=2,
    )
    public_demo_timeout_seconds: float = Field(
        default=float(os.getenv("PUBLIC_DEMO_TIMEOUT_SECONDS", "10")),
        gt=0,
        le=10,
    )
    public_demo_session_timeout_seconds: int = Field(
        default=int(os.getenv("PUBLIC_DEMO_SESSION_TIMEOUT_SECONDS", "1800")),
        ge=60,
        le=1_800,
    )
    public_demo_allowed_extensions: str = os.getenv(
        "PUBLIC_DEMO_ALLOWED_EXTENSIONS",
        ".log,.txt,.csv,.json,.jsonl",
    )
    live_max_raw_lines: int = Field(
        default=int(os.getenv("TRACEHAWK_LIVE_MAX_RAW_LINES", "5000")),
        ge=1,
    )
    live_max_events: int = Field(
        default=int(os.getenv("TRACEHAWK_LIVE_MAX_EVENTS", "5000")),
        ge=1,
    )
    syslog_bind_host: str = os.getenv("TRACEHAWK_SYSLOG_BIND_HOST", "127.0.0.1")
    syslog_udp_port: int = Field(
        default=int(os.getenv("TRACEHAWK_SYSLOG_UDP_PORT", "5514")),
        ge=0,
        le=65535,
    )
    syslog_tcp_port: int = Field(
        default=int(os.getenv("TRACEHAWK_SYSLOG_TCP_PORT", "5514")),
        ge=0,
        le=65535,
    )
    syslog_max_line_bytes: int = Field(
        default=int(os.getenv("TRACEHAWK_SYSLOG_MAX_LINE_BYTES", "8192")),
        ge=128,
        le=1_000_000,
    )
    syslog_queue_size: int = Field(
        default=int(os.getenv("TRACEHAWK_SYSLOG_QUEUE_SIZE", "1000")),
        ge=1,
        le=1_000_000,
    )
    syslog_max_connections: int = Field(
        default=int(os.getenv("TRACEHAWK_SYSLOG_MAX_CONNECTIONS", "32")),
        ge=1,
        le=10_000,
    )
    syslog_idle_timeout_seconds: float = Field(
        default=float(os.getenv("TRACEHAWK_SYSLOG_IDLE_TIMEOUT_SECONDS", "30")),
        gt=0,
        le=3600,
    )
    syslog_batch_size: int = Field(
        default=int(os.getenv("TRACEHAWK_SYSLOG_BATCH_SIZE", "100")),
        ge=1,
        le=100_000,
    )
    syslog_flush_interval_seconds: float = Field(
        default=float(os.getenv("TRACEHAWK_SYSLOG_FLUSH_INTERVAL_SECONDS", "1")),
        gt=0,
        le=300,
    )
    syslog_allow_remote_bind: bool = os.getenv(
        "TRACEHAWK_SYSLOG_ALLOW_REMOTE_BIND", "false"
    ).lower() in {"1", "true", "yes"}
    syslog_stats_interval_seconds: float = Field(
        default=float(os.getenv("TRACEHAWK_SYSLOG_STATS_INTERVAL_SECONDS", "30")),
        gt=0,
        le=3600,
    )


settings = Settings()


def validate_deployment_configuration() -> None:
    if settings.deployment_profile not in SUPPORTED_DEPLOYMENT_PROFILES:
        supported = ", ".join(sorted(SUPPORTED_DEPLOYMENT_PROFILES))
        raise RuntimeError(
            "Unsupported TRACEHAWK_DEPLOYMENT_PROFILE. "
            f"Expected one of: {supported}."
        )
    if settings.deployment_profile == DEPLOYMENT_PROFILE_PUBLIC_DEMO:
        if settings.auth_mode != "disabled":
            raise RuntimeError("Public demo profile requires TRACEHAWK_AUTH_MODE=disabled.")
        if settings.llm_provider != "mock":
            raise RuntimeError("Public demo profile requires TRACEHAWK_LLM_PROVIDER=mock.")
        safe_extensions = {".log", ".txt", ".csv", ".json", ".jsonl"}
        configured_extensions = {
            extension.strip().lower()
            for extension in settings.public_demo_allowed_extensions.split(",")
            if extension.strip()
        }
        if not configured_extensions or not configured_extensions <= safe_extensions:
            raise RuntimeError(
                "Public demo extensions must be a non-empty subset of: "
                + ", ".join(sorted(safe_extensions))
                + "."
            )
