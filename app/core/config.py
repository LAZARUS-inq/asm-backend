from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Database
    database_url: str

    # Redis / Celery
    redis_url: str
    celery_broker_url: str
    celery_result_backend: str

    # Auth
    secret_key: str
    algorithm: str = "HS256"
    # JWT lifetime after magic-link login (default 7 days)
    access_token_expire_minutes: int = 10080
    # Allow /auth/refresh for this many days after JWT exp
    refresh_token_grace_days: int = 30

    # Stripe
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_starter_price_id: str = ""
    stripe_pro_price_id: str = ""

    # NowPayments
    nowpayments_api_key: str = ""
    nowpayments_wallet: str = ""
    api_base_url: str = "http://localhost:8000"
    frontend_url: str = "http://localhost:5173"

    # Resend
    resend_api_key: str = ""
    resend_domain: str = "resend.dev"

    # Shodan
    shodan_api_key: str = ""

    # Scanners (seconds)
    nuclei_subprocess_timeout: int = 600
    nuclei_request_timeout: int = 8
    scan_task_soft_time_limit: int = 1200
    scan_task_time_limit: int = 1260
    # "tags" = filter within NUCLEI_TAGS_ROOT; "dirs" = two web-vuln dirs
    nuclei_scan_mode: str = "tags"
    nuclei_scan_tags: str = "sqli,xss,lfi,exposure,misconfig"
    # When nmap finds nothing: "http" (faster) or "both" (http+https)
    nuclei_fallback_targets: str = "http"
    # Discover URLs/paths on the site (needed for Firing Range, DVWA-style apps)
    nuclei_automatic_scan: bool = True
    nuclei_severity: str = "info,low,medium,high,critical"
    # Drop Cloudflare Workers/Pages noise (edge ports, weak cipher templates)
    scan_suppress_cdn_noise: bool = True

    # App
    environment: str = "development"
    allowed_origins: str = "http://localhost:5173"

    @property
    def origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",")]

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
