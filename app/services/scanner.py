import logging
import os
import platform
import stat
import subprocess
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app.config import Config
from app.services.ip_service import add_scan_session, add_test_result

logger = logging.getLogger(__name__)

RELEASES_URL = (
    "https://github.com/bia-pain-bache/Cloudflare-Clean-IP-Scanner/"
    "releases/download/v2.2.5"
)


@dataclass
class ScanResult:
    ip_address: str
    packets_sent: int
    packets_received: int
    loss_rate: float
    latency_ms: float
    download_speed: float
    colo_code: Optional[str] = None


class CloudflareScanner:
    def __init__(self, app=None):
        self.app = app
        self.binary_path = Config.SCANNER_BINARY
        self._ensure_binary()

    def _get_platform_suffix(self) -> str:
        system = platform.system().lower()
        machine = platform.machine().lower()

        platform_map = {
            ("linux", "x86_64"): "linux-amd64",
            ("linux", "amd64"): "linux-amd64",
            ("linux", "aarch64"): "linux-arm64",
            ("linux", "arm64"): "linux-arm64",
            ("darwin", "arm64"): "darwin-arm64",
            ("darwin", "aarch64"): "darwin-arm64",
            ("darwin", "x86_64"): "darwin-amd64",
            ("darwin", "amd64"): "darwin-amd64",
            ("windows", "amd64"): "windows-amd64",
            ("windows", "x86_64"): "windows-amd64",
        }

        suffix = platform_map.get((system, machine))
        if suffix:
            return suffix

        if system == "linux" and machine.startswith("arm"):
            return "linux-arm7"
        if system == "windows":
            return "windows-386"

        return "linux-amd64"

    def _ensure_binary(self):
        Config.SCANNER_DIR.mkdir(parents=True, exist_ok=True)
        if not self.binary_path.exists():
            logger.info("CloudflareScanner binary not found, downloading...")
            self._download_binary()
        if os.name != "nt":
            st = os.stat(self.binary_path)
            os.chmod(self.binary_path, st.st_mode | stat.S_IEXEC)

    def _download_binary(self):
        suffix = self._get_platform_suffix()
        filename = f"CloudflareScanner_{suffix}.zip"
        url = f"{RELEASES_URL}/{filename}"
        zip_path = Config.SCANNER_DIR / filename

        logger.info(f"Downloading {url}...")
        try:
            urllib.request.urlretrieve(url, zip_path)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(Config.SCANNER_DIR)
            zip_path.unlink()

            for f in Config.SCANNER_DIR.iterdir():
                if f.name.startswith("CloudflareScanner") and f.is_file():
                    if f != self.binary_path:
                        f.rename(self.binary_path)
                    break

            logger.info("CloudflareScanner binary downloaded successfully")
        except Exception as e:
            logger.error(f"Failed to download CloudflareScanner: {e}")
            raise RuntimeError(
                f"Failed to download CloudflareScanner. Please download manually "
                f"from {RELEASES_URL} and place in {Config.SCANNER_DIR}"
            )

    def _create_ip_file(self, ip_ranges: List[str] = None) -> Path:
        if ip_ranges is None:
            ip_ranges = Config.CLOUDFLARE_IPV4_RANGES + Config.CLOUDFLARE_IPV6_RANGES
        ip_file = Config.DATA_DIR / "scan_ips.txt"
        with open(ip_file, "w") as f:
            f.write("\n".join(ip_ranges))
        return ip_file

    def _parse_results(self, result_file: Path) -> List[ScanResult]:
        results = []
        if not result_file.exists():
            logger.warning(f"Result file not found: {result_file}")
            return results

        try:
            with open(result_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or ("IP" in line and "Latency" in line):
                        continue
                    parts = line.split(",")
                    if len(parts) >= 6:
                        try:
                            results.append(
                                ScanResult(
                                    ip_address=parts[0].strip(),
                                    packets_sent=int(parts[1].strip()),
                                    packets_received=int(parts[2].strip()),
                                    loss_rate=float(parts[3].strip()),
                                    latency_ms=float(parts[4].strip()),
                                    download_speed=float(parts[5].strip()),
                                )
                            )
                        except (ValueError, IndexError) as e:
                            logger.debug(f"Failed to parse line: {line}, error: {e}")
        except Exception as e:
            logger.error(f"Failed to read result file: {e}")

        return results

    def _build_command(self, ip_file, result_file, config, extra_args=None):
        cmd = [
            str(self.binary_path),
            "-f", str(ip_file),
            "-o", str(result_file),
            "-n", str(config["threads"]),
            "-url", str(config["url"]),
            "-t", str(config["ping_times"]),
            "-dn", str(config["test_count"]),
            "-dt", str(config["download_timeout"]),
            "-tp", str(config["port"]),
            "-p", "0",
        ]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def initial_scan(
        self,
        ip_ranges=None,
        min_speed=None,
        max_loss=None,
        max_latency=None,
        test_count=None,
        threads=None,
    ) -> Tuple[List[ScanResult], Dict]:
        config = Config.INITIAL_SCAN.copy()
        if min_speed is not None:
            config["min_speed"] = min_speed
        if max_loss is not None:
            config["max_loss_rate"] = max_loss
        if max_latency is not None:
            config["max_latency"] = max_latency
        if test_count is not None:
            config["test_count"] = test_count
        if threads is not None:
            config["threads"] = threads

        ip_file = self._create_ip_file(ip_ranges)
        result_file = Config.DATA_DIR / "initial_scan_result.csv"

        cmd = self._build_command(ip_file, result_file, config, extra_args=[
            "-tl", str(config["max_latency"]),
            "-tlr", str(config["max_loss_rate"]),
            "-sl", str(config["min_speed"]),
        ])

        logger.info(f"Starting initial scan with command: {' '.join(cmd)}")
        start_time = time.time()

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,
                cwd=str(Config.SCANNER_DIR),
            )
        except subprocess.TimeoutExpired:
            logger.error("Initial scan timed out after 1 hour")
            return [], {"error": "timeout"}
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return [], {"error": str(e)}

        duration = time.time() - start_time
        results = self._parse_results(result_file)

        filtered = [
            r
            for r in results
            if r.download_speed >= config["min_speed"]
            and r.loss_rate <= config["max_loss_rate"]
            and r.latency_ms <= config["max_latency"]
        ]

        with self.app.app_context():
            for r in filtered:
                add_test_result(
                    ip_address=r.ip_address,
                    latency_ms=r.latency_ms,
                    download_speed=r.download_speed,
                    loss_rate=r.loss_rate,
                    packets_sent=r.packets_sent,
                    packets_received=r.packets_received,
                    test_type="initial_scan",
                )
            scan_id = add_scan_session(
                total_tested=len(results),
                passed=len(filtered),
                min_speed=config["min_speed"],
                max_latency=config["max_latency"],
                max_loss=config["max_loss_rate"],
                duration=duration,
            )

        metadata = {
            "scan_id": scan_id,
            "total_tested": len(results),
            "passed": len(filtered),
            "duration_seconds": round(duration, 2),
            "config": config,
        }
        logger.info(
            f"Initial scan completed: {len(filtered)} IPs passed out of {len(results)}"
        )
        return filtered, metadata

    def test_specific_ips(self, ip_addresses, timeout=None, threads=None):
        if not ip_addresses:
            return []

        config = Config.MONITOR.copy()
        config["test_count"] = len(ip_addresses)
        if timeout is not None:
            config["download_timeout"] = timeout
        if threads is not None:
            config["threads"] = threads
        config["threads"] = min(config["threads"], len(ip_addresses))

        ip_file = Config.DATA_DIR / "monitor_ips.txt"
        with open(ip_file, "w") as f:
            for ip in ip_addresses:
                suffix = "/128" if ":" in ip else "/32"
                f.write(f"{ip}{suffix}\n")

        result_file = Config.DATA_DIR / "monitor_result.csv"

        cmd = self._build_command(ip_file, result_file, config, extra_args=["-allip"])

        logger.debug(f"Testing {len(ip_addresses)} IPs...")
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(Config.SCANNER_DIR),
            )
        except subprocess.TimeoutExpired:
            logger.warning("Periodic test timed out")
            return []
        except Exception as e:
            logger.error(f"Test failed: {e}")
            return []

        results = self._parse_results(result_file)

        with self.app.app_context():
            for r in results:
                add_test_result(
                    ip_address=r.ip_address,
                    latency_ms=r.latency_ms,
                    download_speed=r.download_speed,
                    loss_rate=r.loss_rate,
                    packets_sent=r.packets_sent,
                    packets_received=r.packets_received,
                    test_type="periodic",
                )

        return results
