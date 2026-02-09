import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).parent.parent.absolute()

load_dotenv(BASE_DIR / ".env")


def _env(key, default=None, cast=None):
    """Read an env var with optional type casting."""
    value = os.environ.get(key, default)
    if value is None:
        return None
    if cast is not None and not isinstance(value, cast):
        return cast(value)
    return value


def _env_list(key, default=""):
    """Read a comma-separated env var into a list."""
    raw = os.environ.get(key, default)
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


class Config:
    # Directories
    BASE_DIR = BASE_DIR
    DATA_DIR = Path(_env("DATA_DIR", str(BASE_DIR / "data")))
    LOGS_DIR = Path(_env("LOGS_DIR", str(BASE_DIR / "logs")))
    SCANNER_DIR = Path(_env("SCANNER_DIR", str(BASE_DIR / "scanner")))

    # Database
    SQLALCHEMY_DATABASE_URI = _env(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR / 'data' / 'cloudflare_ips.db'}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Scanner binary
    SCANNER_BINARY = Path(
        _env("SCANNER_BINARY", str(BASE_DIR / "scanner" / "CloudflareScanner"))
    )

    # Initial scan parameters
    INITIAL_SCAN = {
        "min_speed": _env("SCAN_MIN_SPEED", 10.0, float),
        "max_loss_rate": _env("SCAN_MAX_LOSS_RATE", 0.25, float),
        "max_latency": _env("SCAN_MAX_LATENCY", 1000, int),
        "test_count": _env("SCAN_TEST_COUNT", 50, int),
        "threads": _env("SCAN_THREADS", 300, int),
        "ping_times": _env("SCAN_PING_TIMES", 4, int),
        "download_timeout": _env("SCAN_DOWNLOAD_TIMEOUT", 15, int),
        "port": _env("SCAN_PORT", 443, int),
        "url": _env(
            "SCAN_URL",
            "https://speed.cloudflare.com/__down?bytes=52428800",
        ),
        "httping": _env("SCAN_HTTPING", "true").lower() in ("true", "1", "yes"),
        "httping_code": _env("SCAN_HTTPING_CODE", "200"),
        "schedule_interval": _env("SCAN_SCHEDULE_INTERVAL", 0, int),
    }

    # Monitor parameters
    MONITOR = {
        "interval_seconds": _env("MONITOR_INTERVAL", 120, int),
        "download_timeout": _env("MONITOR_DOWNLOAD_TIMEOUT", 10, int),
        "ping_times": _env("MONITOR_PING_TIMES", 4, int),
        "threads": _env("MONITOR_THREADS", 100, int),
        "max_ips_per_cycle": _env("MONITOR_MAX_IPS", 20, int),
        "port": _env("MONITOR_PORT", 443, int),
        "url": _env(
            "MONITOR_URL",
            "https://speed.cloudflare.com/__down?bytes=52428800",
        ),
        "httping": _env("MONITOR_HTTPING", "true").lower() in ("true", "1", "yes"),
        "httping_code": _env("MONITOR_HTTPING_CODE", "200"),
    }

    # Cleanup parameters
    CLEANUP = {
        "enabled": _env("CLEANUP_ENABLED", "true").lower() in ("true", "1", "yes"),
        "no_speed_tests": _env("CLEANUP_NO_SPEED_TESTS", 10, int),
        "min_speed": _env("CLEANUP_MIN_SPEED", 0, float),
        "min_speed_enabled": _env("CLEANUP_MIN_SPEED_ENABLED", "false").lower()
        in ("true", "1", "yes"),
    }

    # Dashboard
    DASHBOARD_HOST = _env("DASHBOARD_HOST", "0.0.0.0")
    DASHBOARD_PORT = _env("DASHBOARD_PORT", 8080, int)

    # Data retention
    RETENTION_DAYS = _env("RETENTION_DAYS", 30, int)

    # Cloudflare IP ranges
    CLOUDFLARE_IPV4_RANGES = _env_list(
        "CLOUDFLARE_IPV4_RANGES",
        "173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,"
        "141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,"
        "197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,"
        "104.24.0.0/14,172.64.0.0/13,131.0.72.0/22",
    )

    CLOUDFLARE_IPV6_RANGES = _env_list(
        "CLOUDFLARE_IPV6_RANGES",
        "2400:cb00::/32,2606:4700::/32,2803:f800::/32,"
        "2405:b500::/32,2405:8100::/32,2a06:98c0::/29,2c0f:f248::/32",
    )

    # Logging
    LOG_FORMAT = _env(
        "LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    LOG_LEVEL = _env("LOG_LEVEL", "INFO")
