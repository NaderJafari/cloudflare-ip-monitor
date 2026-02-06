#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare IP Monitor - Configuration
Central configuration for all components
"""

import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).parent.absolute()
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
SCANNER_DIR = BASE_DIR / "scanner"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# Database
DATABASE_PATH = DATA_DIR / "cloudflare_ips.db"

# CloudflareScanner binary path (download from releases)
SCANNER_BINARY = SCANNER_DIR / "CloudflareScanner"

# Initial scan parameters (Step 1: Gather IPs from ALL Cloudflare ranges)
INITIAL_SCAN_CONFIG = {
    "min_speed": 10.0,           # MB/s - Download speed >= 10MB/s
    "max_loss_rate": 0.25,       # Loss rate < 0.25 (25%)
    "max_latency": 1000,         # ms - Delay < 1000ms
    "test_count": 50,            # Number of IPs to test for download speed
    "threads": 300,              # Concurrent latency test threads
    "ping_times": 4,             # Ping count per IP
    "download_timeout": 15,      # Seconds per download test
    "port": 443,                 # Test port
    "url": "https://speed.cloudflare.com/__down?bytes=52428800",                 # Test port
}

# Periodic monitoring parameters (Step 2: Re-test selected IPs)
MONITOR_CONFIG = {
    "interval_seconds": 120,     # Default: every 2 minutes
    "download_timeout": 10,      # Seconds per download test
    "ping_times": 4,             # Ping count per IP
    "threads": 100,              # Concurrent threads for periodic tests
    "max_ips_per_cycle": 20,     # Max IPs to test per cycle
    "port": 443,                 # Test port
    "url": "https://speed.cloudflare.com/__down?bytes=52428800",
}

# Dashboard configuration (Step 3: Web interface)
DASHBOARD_CONFIG = {
    "host": "0.0.0.0",
    "port": 8080,
    "debug": False,
}

# Data retention
RETENTION_DAYS = 30  # Keep historical data for 30 days

# Cloudflare IP ranges (official source)
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

# Logging configuration
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"
