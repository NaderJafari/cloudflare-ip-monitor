from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.absolute()


class Config:
    BASE_DIR = BASE_DIR
    DATA_DIR = BASE_DIR / "data"
    LOGS_DIR = BASE_DIR / "logs"
    SCANNER_DIR = BASE_DIR / "scanner"

    SQLALCHEMY_DATABASE_URI = f"sqlite:///{BASE_DIR / 'data' / 'cloudflare_ips.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SCANNER_BINARY = BASE_DIR / "scanner" / "CloudflareScanner"

    INITIAL_SCAN = {
        "min_speed": 10.0,
        "max_loss_rate": 0.25,
        "max_latency": 1000,
        "test_count": 50,
        "threads": 300,
        "ping_times": 4,
        "download_timeout": 15,
        "port": 443,
        "url": "https://speed.cloudflare.com/__down?bytes=52428800",
    }

    MONITOR = {
        "interval_seconds": 120,
        "download_timeout": 10,
        "ping_times": 4,
        "threads": 100,
        "max_ips_per_cycle": 20,
        "port": 443,
        "url": "https://speed.cloudflare.com/__down?bytes=52428800",
    }

    DASHBOARD_HOST = "0.0.0.0"
    DASHBOARD_PORT = 8080

    RETENTION_DAYS = 30

    CLOUDFLARE_IPV4_RANGES = [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    ]

    CLOUDFLARE_IPV6_RANGES = [
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ]

    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_LEVEL = "INFO"
