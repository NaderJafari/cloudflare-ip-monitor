import logging
import os
import platform
import shutil
import stat
import subprocess
import threading
import time
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app.config import Config
from app.services.ip_service import add_scan_session, add_test_result

logger = logging.getLogger(__name__)

RELEASES_URL = (
    "https://github.com/bia-pain-bache/Cloudflare-Clean-IP-Scanner/"
    "releases/download/v2.2.5"
)


class ScanCancelled(Exception):
    pass


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

        # Scan lock & cancellation
        self._lock = threading.Lock()
        self._process: Optional[subprocess.Popen] = None
        self._cancel_event = threading.Event()
        self._is_scanning = False
        self._scan_start_time: Optional[float] = None
        self._last_scan_result: Optional[dict] = None

        # Periodic schedule
        self._schedule_interval = Config.INITIAL_SCAN.get("schedule_interval", 0)
        self._schedule_stop = threading.Event()
        self._schedule_thread: Optional[threading.Thread] = None
        self._schedule_running = False
        self._schedule_last_run: Optional[str] = None
        self._schedule_scan_count = 0

        logger.info(f"Initializing CloudflareScanner (binary: {self.binary_path})")
        self._ensure_binary()
        logger.info("CloudflareScanner initialized successfully")

    # ── Binary management ────────────────────────────────────────

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

    # ── Thread-safe helpers ──────────────────────────────────────

    @staticmethod
    def _temp_files(prefix: str) -> Tuple[Path, Path, Path]:
        """Create unique file paths and working directory so concurrent runs never collide."""
        uid = uuid.uuid4().hex[:8]
        ip_file = Config.DATA_DIR / f"{prefix}_ips_{uid}.txt"
        result_file = Config.DATA_DIR / f"{prefix}_result_{uid}.csv"
        work_dir = Config.DATA_DIR / f"{prefix}_work_{uid}"
        work_dir.mkdir(parents=True, exist_ok=True)
        return ip_file, result_file, work_dir

    @staticmethod
    def _cleanup(*paths: Path):
        for p in paths:
            try:
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    p.unlink(missing_ok=True)
            except OSError:
                pass

    def _run_process(self, cmd, timeout=3600, cwd=None):
        """Run the scanner binary with cancellation and timeout support.

        Uses Popen so the process can be terminated mid-flight via
        ``cancel_scan()``.  Stdout/stderr are drained in background
        threads to prevent pipe-buffer deadlocks.
        """
        self._cancel_event.clear()
        logger.debug(f"Launching process: {' '.join(str(c) for c in cmd)}")
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd or Config.SCANNER_DIR),
        )
        logger.debug(f"Process started with PID {self._process.pid}")

        # Drain stdout/stderr in background threads to prevent deadlock.
        # Without draining, the OS pipe buffer (~64 KB) fills up and the
        # child process blocks on write, causing the poll loop to hang.
        stdout_lines = []
        stderr_lines = []

        def _drain(stream, sink):
            try:
                for raw_line in stream:
                    sink.append(raw_line)
            except Exception:
                pass
            finally:
                stream.close()

        t_out = threading.Thread(target=_drain, args=(self._process.stdout, stdout_lines), daemon=True)
        t_err = threading.Thread(target=_drain, args=(self._process.stderr, stderr_lines), daemon=True)
        t_out.start()
        t_err.start()

        try:
            deadline = time.time() + timeout
            while self._process.poll() is None:
                if self._cancel_event.is_set():
                    logger.info(f"Cancellation requested, terminating PID {self._process.pid}")
                    self._process.terminate()
                    try:
                        self._process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        logger.warning(f"Process did not terminate gracefully, killing PID {self._process.pid}")
                        self._process.kill()
                        self._process.wait()
                    raise ScanCancelled()
                if time.time() > deadline:
                    logger.error(f"Process timed out after {timeout}s, killing PID {self._process.pid}")
                    self._process.kill()
                    self._process.wait()
                    raise subprocess.TimeoutExpired(cmd, timeout)
                time.sleep(0.5)

            # Wait for drain threads to finish reading remaining output
            t_out.join(timeout=5)
            t_err.join(timeout=5)

            rc = self._process.returncode
            stdout_text = b"".join(stdout_lines).decode("utf-8", errors="replace").strip()
            stderr_text = b"".join(stderr_lines).decode("utf-8", errors="replace").strip()

            if stdout_text:
                for line in stdout_text.splitlines()[:50]:
                    logger.debug(f"[scanner stdout] {line}")
            if stderr_text:
                for line in stderr_text.splitlines()[:50]:
                    logger.warning(f"[scanner stderr] {line}")

            if rc != 0:
                logger.warning(f"Scanner process exited with code {rc}")

            return rc
        finally:
            self._process = None

    # ── Parsing ──────────────────────────────────────────────────

    def _parse_results(self, result_file: Path) -> List[ScanResult]:
        results = []
        if not result_file.exists():
            logger.warning(f"Result file not found: {result_file}")
            return results

        skipped_lines = 0
        parse_errors = 0
        try:
            with open(result_file, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or ("IP" in line and "Latency" in line):
                        skipped_lines += 1
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
                            parse_errors += 1
                            logger.debug(
                                f"Failed to parse line {line_num}: "
                                f"{line!r}, error: {e}"
                            )
                    else:
                        parse_errors += 1
                        logger.debug(
                            f"Line {line_num} has {len(parts)} fields "
                            f"(expected >= 6): {line!r}"
                        )
        except Exception as e:
            logger.error(f"Failed to read result file {result_file}: {e}")

        logger.info(
            f"Parsed result file: {len(results)} valid entries, "
            f"{parse_errors} errors, {skipped_lines} skipped"
        )
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
        ]
        if config.get("httping"):
            cmd.append("-httping")
            httping_code = config.get("httping_code")
            if httping_code:
                cmd.extend(["-httping-code", str(httping_code)])
        else:
            cmd.extend(["-p", "0"])
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    # ── Initial scan ─────────────────────────────────────────────

    def initial_scan(
        self,
        ip_ranges=None,
        min_speed=None,
        max_loss=None,
        max_latency=None,
        test_count=None,
        threads=None,
    ) -> Tuple[List[ScanResult], Dict]:
        if not self._lock.acquire(blocking=False):
            logger.info("Initial scan skipped: another scan is already running")
            return [], {"status": "skipped", "reason": "scan already running"}

        ip_file, result_file, work_dir = self._temp_files("scan")
        try:
            self._is_scanning = True
            self._scan_start_time = time.time()
            self._cancel_event.clear()

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

            logger.info(
                "Initial scan starting with config: "
                f"min_speed={config['min_speed']} MB/s, "
                f"max_latency={config['max_latency']} ms, "
                f"max_loss_rate={config['max_loss_rate']}, "
                f"test_count={config['test_count']}, "
                f"threads={config['threads']}, "
                f"httping={config.get('httping', False)}"
            )

            if ip_ranges is None:
                ip_ranges = (
                    Config.CLOUDFLARE_IPV4_RANGES + Config.CLOUDFLARE_IPV6_RANGES
                )
            logger.info(f"Writing {len(ip_ranges)} IP ranges to {ip_file}")
            with open(ip_file, "w") as f:
                f.write("\n".join(ip_ranges))

            cmd = self._build_command(
                ip_file,
                result_file,
                config,
                extra_args=[
                    "-tl", str(config["max_latency"]),
                    "-tlr", str(config["max_loss_rate"]),
                    "-sl", str(config["min_speed"]),
                ],
            )

            logger.info("Launching scanner binary for initial scan...")
            rc = self._run_process(cmd, timeout=3600, cwd=work_dir)
            duration = time.time() - self._scan_start_time
            logger.info(
                f"Scanner process finished in {duration:.1f}s "
                f"with exit code {rc}"
            )

            if not result_file.exists():
                logger.warning(
                    f"Result file {result_file} not found after scan "
                    f"(exit code {rc}). Scanner may have failed."
                )
            else:
                result_size = result_file.stat().st_size
                logger.info(f"Result file size: {result_size} bytes")

            results = self._parse_results(result_file)
            logger.info(f"Parsed {len(results)} total IPs from scanner output")

            filtered = [
                r
                for r in results
                if r.download_speed >= config["min_speed"]
                and r.loss_rate <= config["max_loss_rate"]
                and r.latency_ms <= config["max_latency"]
            ]
            logger.info(
                f"Filtered results: {len(filtered)}/{len(results)} IPs "
                f"passed criteria"
            )

            if filtered:
                best = max(filtered, key=lambda r: r.download_speed)
                logger.info(
                    f"Best IP: {best.ip_address} "
                    f"(speed={best.download_speed:.2f} MB/s, "
                    f"latency={best.latency_ms:.0f} ms, "
                    f"loss={best.loss_rate:.2%})"
                )

            logger.info("Saving results to database...")
            with self.app.app_context():
                for i, r in enumerate(filtered):
                    add_test_result(
                        ip_address=r.ip_address,
                        latency_ms=r.latency_ms,
                        download_speed=r.download_speed,
                        loss_rate=r.loss_rate,
                        packets_sent=r.packets_sent,
                        packets_received=r.packets_received,
                        test_type="initial_scan",
                    )
                    if (i + 1) % 10 == 0:
                        logger.debug(f"Saved {i + 1}/{len(filtered)} IPs to database")
                scan_id = add_scan_session(
                    total_tested=len(results),
                    passed=len(filtered),
                    min_speed=config["min_speed"],
                    max_latency=config["max_latency"],
                    max_loss=config["max_loss_rate"],
                    duration=duration,
                )
            logger.info(
                f"Database updated: {len(filtered)} IPs saved, "
                f"scan session #{scan_id} recorded"
            )

            metadata = {
                "status": "completed",
                "scan_id": scan_id,
                "total_tested": len(results),
                "passed": len(filtered),
                "duration_seconds": round(duration, 2),
                "config": config,
            }
            self._last_scan_result = metadata
            logger.info(
                f"Initial scan completed successfully: "
                f"{len(filtered)} IPs passed out of {len(results)} "
                f"in {duration:.1f}s"
            )
            return filtered, metadata

        except ScanCancelled:
            duration = time.time() - (self._scan_start_time or time.time())
            logger.info(f"Initial scan was cancelled after {duration:.1f}s")
            meta = {"status": "cancelled"}
            self._last_scan_result = meta
            return [], meta

        except subprocess.TimeoutExpired:
            logger.error("Initial scan timed out after 1 hour")
            meta = {"status": "timeout"}
            self._last_scan_result = meta
            return [], meta

        except Exception as e:
            logger.error(f"Initial scan failed with error: {e}", exc_info=True)
            meta = {"status": "error", "error": str(e)}
            self._last_scan_result = meta
            return [], meta

        finally:
            logger.debug(f"Cleaning up temp files: {ip_file}, {result_file}, {work_dir}")
            self._cleanup(ip_file, result_file, work_dir)
            self._is_scanning = False
            self._scan_start_time = None
            self._lock.release()
            logger.debug("Scan lock released")

    # ── Periodic tests (used by monitor) ─────────────────────────

    def test_specific_ips(self, ip_addresses, timeout=None, threads=None):
        if not ip_addresses:
            logger.debug("test_specific_ips called with empty IP list, skipping")
            return []

        config = Config.MONITOR.copy()
        config["test_count"] = len(ip_addresses)
        if timeout is not None:
            config["download_timeout"] = timeout
        if threads is not None:
            config["threads"] = threads
        config["threads"] = min(config["threads"], len(ip_addresses))

        logger.info(
            f"Testing {len(ip_addresses)} specific IPs "
            f"(threads={config['threads']}, "
            f"timeout={config['download_timeout']}s)"
        )

        ip_file, result_file, work_dir = self._temp_files("monitor")
        try:
            with open(ip_file, "w") as f:
                for ip in ip_addresses:
                    suffix = "/128" if ":" in ip else "/32"
                    f.write(f"{ip}{suffix}\n")

            cmd = self._build_command(
                ip_file, result_file, config, extra_args=["-allip"]
            )

            logger.debug(f"Monitor scan command: {' '.join(str(c) for c in cmd)}")
            start_time = time.time()
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(work_dir),
            )
            elapsed = time.time() - start_time

            if proc.returncode != 0:
                logger.warning(
                    f"Monitor scan exited with code {proc.returncode} "
                    f"after {elapsed:.1f}s"
                )
                if proc.stderr:
                    for line in proc.stderr.strip().splitlines()[:20]:
                        logger.warning(f"[monitor stderr] {line}")

            results = self._parse_results(result_file)
            logger.info(
                f"Monitor scan completed in {elapsed:.1f}s: "
                f"{len(results)}/{len(ip_addresses)} IPs returned results"
            )

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
            logger.debug(f"Saved {len(results)} periodic test results to database")

            return results

        except subprocess.TimeoutExpired:
            logger.warning(
                f"Periodic test timed out after 300s "
                f"for {len(ip_addresses)} IPs"
            )
            return []
        except Exception as e:
            logger.error(f"Periodic test failed: {e}", exc_info=True)
            return []
        finally:
            self._cleanup(ip_file, result_file, work_dir)

    # ── Cancellation & status ────────────────────────────────────

    def cancel_scan(self) -> bool:
        """Cancel the currently running initial scan."""
        if self._is_scanning:
            logger.info("Scan cancellation requested")
            self._cancel_event.set()
            return True
        logger.debug("Cancel requested but no scan is running")
        return False

    def get_scan_status(self) -> dict:
        elapsed = None
        if self._scan_start_time:
            elapsed = int(time.time() - self._scan_start_time)
        return {
            "is_scanning": self._is_scanning,
            "elapsed_seconds": elapsed,
            "last_result": self._last_scan_result,
            "schedule": {
                "is_running": self._schedule_running,
                "interval_seconds": self._schedule_interval,
                "last_run": self._schedule_last_run,
                "scan_count": self._schedule_scan_count,
            },
        }

    # ── Periodic scan scheduler ──────────────────────────────────

    def _schedule_loop(self):
        logger.info("Scan schedule loop started")
        while not self._schedule_stop.is_set():
            logger.info(
                f"Scheduled scan #{self._schedule_scan_count + 1} starting..."
            )
            try:
                _, meta = self.initial_scan()
                status = meta.get("status", "unknown")
                if status == "completed":
                    self._schedule_scan_count += 1
                    self._schedule_last_run = datetime.now().isoformat()
                    logger.info(
                        f"Scheduled scan completed "
                        f"(total completed: {self._schedule_scan_count})"
                    )
                elif status == "skipped":
                    logger.info("Scheduled scan skipped: another scan in progress")
                else:
                    logger.warning(f"Scheduled scan ended with status: {status}")
            except Exception as e:
                logger.error(f"Scheduled scan failed: {e}", exc_info=True)

            logger.debug(
                f"Waiting {self._schedule_interval}s until next scheduled scan"
            )
            self._schedule_stop.wait(self._schedule_interval)
        logger.info("Scan schedule loop exited")

    def start_schedule(self, interval=None):
        if self._schedule_running:
            return

        if interval is not None:
            self._schedule_interval = max(60, interval)
        if self._schedule_interval <= 0:
            logger.warning("Schedule interval must be > 0")
            return

        self._schedule_stop.clear()
        self._schedule_running = True
        self._schedule_thread = threading.Thread(
            target=self._schedule_loop, daemon=True
        )
        self._schedule_thread.start()
        logger.info(
            f"Scan scheduler started (interval: {self._schedule_interval}s)"
        )

    def stop_schedule(self):
        if not self._schedule_running:
            return

        self._schedule_stop.set()

        if self._schedule_thread:
            self._schedule_thread.join(timeout=5)

        self._schedule_running = False
        logger.info("Scan scheduler stopped")

    def set_schedule_interval(self, seconds: int):
        self._schedule_interval = max(60, seconds)
        logger.info(f"Scan schedule interval changed to {self._schedule_interval}s")
