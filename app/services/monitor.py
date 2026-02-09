import logging
import threading
import time
from datetime import datetime
from typing import Callable, List, Optional

from app.config import Config
from app.services.ip_service import (
    cleanup_dead_ips,
    cleanup_old_data,
    cleanup_slow_ips,
    get_active_ips,
)

logger = logging.getLogger(__name__)


class PeriodicMonitor:
    def __init__(self, app=None):
        self.app = app
        self.interval = Config.MONITOR["interval_seconds"]
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._is_running = False
        self._last_test_time: Optional[datetime] = None
        self._test_count = 0
        self._callbacks: List[Callable] = []

    def add_callback(self, callback: Callable):
        self._callbacks.append(callback)

    def _notify_callbacks(self, results):
        for cb in self._callbacks:
            try:
                cb(results)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    def _test_cycle(self):
        logger.info("Starting periodic test cycle...")
        try:
            with self.app.app_context():
                active_ips = get_active_ips()

            if not active_ips:
                logger.warning("No active IPs to test. Run initial scan first.")
                return []

            all_ip_list = [ip["ip_address"] for ip in active_ips]
            batch_size = Config.MONITOR["max_ips_per_cycle"]
            total = len(all_ip_list)
            logger.info(
                f"Testing all {total} active IPs in batches of {batch_size}..."
            )

            all_results = []
            for i in range(0, total, batch_size):
                batch = all_ip_list[i : i + batch_size]
                batch_num = (i // batch_size) + 1
                total_batches = (total + batch_size - 1) // batch_size
                logger.info(
                    f"Testing batch {batch_num}/{total_batches} "
                    f"({len(batch)} IPs)..."
                )

                results = self.app.scanner.test_specific_ips(
                    ip_addresses=batch,
                    timeout=Config.MONITOR["download_timeout"],
                    threads=Config.MONITOR["threads"],
                )
                all_results.extend(results)

                if self._stop_event.is_set():
                    logger.info("Monitor stop requested, aborting remaining batches")
                    break

            self._last_test_time = datetime.now()
            self._test_count += 1
            logger.info(
                f"Test cycle completed: {len(all_results)} results "
                f"from {total} IPs"
            )

            self._notify_callbacks(all_results)
            return all_results

        except Exception as e:
            logger.error(f"Test cycle failed: {e}")
            return []

    def _cleanup_cycle(self):
        try:
            with self.app.app_context():
                cleanup_old_data(Config.RETENTION_DAYS)
                if Config.CLEANUP["enabled"]:
                    cleanup_dead_ips(Config.CLEANUP["no_speed_tests"])
                if Config.CLEANUP.get("min_speed_enabled") and Config.CLEANUP.get("min_speed", 0) > 0:
                    cleanup_slow_ips(Config.CLEANUP["min_speed"])
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

    def _monitor_loop(self):
        cleanup_counter = 0
        while not self._stop_event.is_set():
            self._test_cycle()
            cleanup_counter += 1
            if cleanup_counter >= 24:
                self._cleanup_cycle()
                cleanup_counter = 0
            self._stop_event.wait(self.interval)

    def start(self, run_immediately=True):
        if self._is_running:
            logger.warning("Monitor is already running")
            return

        self._stop_event.clear()
        self._is_running = True

        if run_immediately:
            self._test_cycle()

        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info(f"Periodic monitor started (interval: {self.interval}s)")

    def stop(self, timeout=10.0):
        if not self._is_running:
            return

        logger.info("Stopping periodic monitor...")
        self._stop_event.set()

        if self._thread:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning("Monitor thread did not stop gracefully")

        self._is_running = False
        logger.info("Periodic monitor stopped")

    def is_running(self) -> bool:
        return self._is_running

    def get_status(self) -> dict:
        return {
            "is_running": self._is_running,
            "interval_seconds": self.interval,
            "last_test_time": (
                self._last_test_time.isoformat() if self._last_test_time else None
            ),
            "test_count": self._test_count,
            "next_test_in": self._calculate_next_test(),
        }

    def _calculate_next_test(self) -> Optional[int]:
        if not self._is_running or not self._last_test_time:
            return None
        elapsed = (datetime.now() - self._last_test_time).total_seconds()
        return max(0, int(self.interval - elapsed))

    def set_interval(self, seconds: int):
        self.interval = max(30, seconds)
        logger.info(f"Monitor interval changed to {self.interval}s")

    def trigger_immediate_test(self) -> list:
        return self._test_cycle()
