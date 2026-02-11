import logging
import threading
import time
from collections import deque
from datetime import datetime
from typing import Callable, List, Optional

from app.config import Config
from app.services.ip_service import (
    add_test_result,
    cleanup_dead_ips,
    cleanup_old_data,
    cleanup_slow_ips,
    get_active_ips,
)

logger = logging.getLogger(__name__)

# Keep last 50 cycle summaries in memory
MAX_CYCLE_HISTORY = 50


class PeriodicMonitor:
    def __init__(self, app=None):
        self.app = app
        self.interval = Config.MONITOR["interval_seconds"]
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()  # when set, cycle is paused
        self._thread: Optional[threading.Thread] = None
        self._is_running = False
        self._is_paused = False
        self._last_test_time: Optional[datetime] = None
        self._test_count = 0
        self._callbacks: List[Callable] = []

        # Live progress tracking
        self._cycle_progress = {
            "active": False,
            "current_batch": 0,
            "total_batches": 0,
            "ips_tested": 0,
            "ips_total": 0,
            "ips_responded": 0,
            "ips_failed": 0,
            "started_at": None,
            "elapsed_seconds": 0,
        }

        # Cycle history log
        self._cycle_history: deque = deque(maxlen=MAX_CYCLE_HISTORY)

        # Last cycle summary
        self._last_cycle_summary = None

    def add_callback(self, callback: Callable):
        self._callbacks.append(callback)

    def _notify_callbacks(self, results):
        for cb in self._callbacks:
            try:
                cb(results)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    def _reset_progress(self, total_ips=0, total_batches=0):
        self._cycle_progress = {
            "active": True,
            "current_batch": 0,
            "total_batches": total_batches,
            "ips_tested": 0,
            "ips_total": total_ips,
            "ips_responded": 0,
            "ips_failed": 0,
            "started_at": datetime.now().isoformat(),
            "elapsed_seconds": 0,
        }

    def _update_progress(self, batch_num, ips_in_batch, responded, failed):
        self._cycle_progress["current_batch"] = batch_num
        self._cycle_progress["ips_tested"] += ips_in_batch
        self._cycle_progress["ips_responded"] += responded
        self._cycle_progress["ips_failed"] += failed
        if self._cycle_progress["started_at"]:
            start = datetime.fromisoformat(self._cycle_progress["started_at"])
            self._cycle_progress["elapsed_seconds"] = round(
                (datetime.now() - start).total_seconds(), 1
            )

    def _finish_progress(self):
        self._cycle_progress["active"] = False

    def _test_cycle(self):
        logger.info("Starting periodic test cycle...")
        cycle_start = time.time()
        try:
            with self.app.app_context():
                active_ips = get_active_ips()

            if not active_ips:
                logger.warning("No active IPs to test. Run initial scan first.")
                return []

            all_ip_list = [ip["ip_address"] for ip in active_ips]
            batch_size = Config.MONITOR["max_ips_per_cycle"]
            total = len(all_ip_list)
            total_batches = (total + batch_size - 1) // batch_size
            logger.info(
                f"Testing all {total} active IPs in batches of {batch_size}..."
            )

            self._reset_progress(total_ips=total, total_batches=total_batches)

            all_results = []
            all_responded_ips = set()

            for i in range(0, total, batch_size):
                # Check pause
                while self._is_paused and not self._stop_event.is_set():
                    self._pause_event.wait(1)

                batch = all_ip_list[i : i + batch_size]
                batch_num = (i // batch_size) + 1
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

                # Track which IPs responded
                responded_ips = {r.ip_address for r in results}
                all_responded_ips.update(responded_ips)

                # IPs that didn't respond in this batch
                failed_ips = [ip for ip in batch if ip not in responded_ips]
                failed_count = len(failed_ips)

                # Insert failed test results for IPs with no response
                if failed_ips:
                    logger.info(
                        f"Batch {batch_num}: {failed_count} IPs had no response, "
                        f"inserting failed test results"
                    )
                    with self.app.app_context():
                        for ip_addr in failed_ips:
                            add_test_result(
                                ip_address=ip_addr,
                                latency_ms=0,
                                download_speed=0,
                                loss_rate=1.0,
                                packets_sent=10,
                                packets_received=0,
                                test_type="periodic",
                            )

                self._update_progress(
                    batch_num, len(batch), len(responded_ips), failed_count
                )

                if self._stop_event.is_set():
                    logger.info("Monitor stop requested, aborting remaining batches")
                    break

            cycle_duration = round(time.time() - cycle_start, 2)
            self._last_test_time = datetime.now()
            self._test_count += 1
            self._finish_progress()

            total_responded = len(all_responded_ips)
            total_failed = total - total_responded

            # Compute avg speed from results
            avg_speed = 0
            if all_results:
                avg_speed = round(
                    sum(r.download_speed for r in all_results) / len(all_results), 2
                )

            summary = {
                "cycle_number": self._test_count,
                "timestamp": self._last_test_time.isoformat(),
                "duration_seconds": cycle_duration,
                "ips_total": total,
                "ips_responded": total_responded,
                "ips_failed": total_failed,
                "results_count": len(all_results),
                "avg_speed": avg_speed,
                "batches": total_batches,
            }
            self._last_cycle_summary = summary
            self._cycle_history.appendleft(summary)

            logger.info(
                f"Test cycle #{self._test_count} completed: "
                f"{total_responded}/{total} responded, "
                f"{total_failed} failed, "
                f"avg speed {avg_speed} MB/s, "
                f"duration {cycle_duration}s"
            )

            self._notify_callbacks(all_results)
            return all_results

        except Exception as e:
            logger.error(f"Test cycle failed: {e}")
            self._finish_progress()
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
        self._pause_event.clear()
        self._is_paused = False
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
        self._pause_event.set()  # unblock if paused

        if self._thread:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning("Monitor thread did not stop gracefully")

        self._is_running = False
        self._is_paused = False
        logger.info("Periodic monitor stopped")

    def pause(self):
        if self._is_running and not self._is_paused:
            self._is_paused = True
            self._pause_event.clear()
            logger.info("Monitor paused")

    def resume(self):
        if self._is_running and self._is_paused:
            self._is_paused = False
            self._pause_event.set()
            logger.info("Monitor resumed")

    def is_running(self) -> bool:
        return self._is_running

    def get_status(self) -> dict:
        return {
            "is_running": self._is_running,
            "is_paused": self._is_paused,
            "interval_seconds": self.interval,
            "last_test_time": (
                self._last_test_time.isoformat() if self._last_test_time else None
            ),
            "test_count": self._test_count,
            "next_test_in": self._calculate_next_test(),
            "batch_size": Config.MONITOR["max_ips_per_cycle"],
        }

    def get_cycle_progress(self) -> dict:
        return dict(self._cycle_progress)

    def get_last_cycle_summary(self) -> Optional[dict]:
        return self._last_cycle_summary

    def get_cycle_history(self, limit=20) -> list:
        return list(self._cycle_history)[:limit]

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
