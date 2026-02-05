#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare IP Monitor - Periodic Monitor Module
Handles scheduled periodic testing of discovered IPs
"""

import threading
import time
import logging
import signal
import sys
from datetime import datetime
from typing import List, Optional, Callable

from config import MONITOR_CONFIG, RETENTION_DAYS
from database import db
from scanner import run_periodic_test, run_initial_scan

logger = logging.getLogger(__name__)


class PeriodicMonitor:
    """
    Handles periodic testing of Cloudflare IPs
    
    Features:
    - Configurable test interval
    - Automatic cleanup of old data
    - Thread-safe operation
    - Graceful shutdown
    """
    
    def __init__(self, interval_seconds: int = None):
        self.interval = interval_seconds or MONITOR_CONFIG['interval_seconds']
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._is_running = False
        self._last_test_time: Optional[datetime] = None
        self._test_count = 0
        self._callbacks: List[Callable] = []
    
    def add_callback(self, callback: Callable):
        """Add callback to be called after each test cycle"""
        self._callbacks.append(callback)
    
    def _notify_callbacks(self, results):
        """Notify all registered callbacks"""
        for callback in self._callbacks:
            try:
                callback(results)
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    def _test_cycle(self):
        """Perform one test cycle"""
        logger.info("Starting periodic test cycle...")
        
        try:
            # Get active IPs to test
            active_ips = db.get_active_ips(limit=MONITOR_CONFIG['max_ips_per_cycle'])
            
            if not active_ips:
                logger.warning("No active IPs to test. Run initial scan first.")
                return []
            
            ip_list = [ip['ip_address'] for ip in active_ips]
            logger.info(f"Testing {len(ip_list)} IPs...")
            
            # Run tests
            results = run_periodic_test(
                ip_addresses=ip_list,
                timeout=MONITOR_CONFIG['download_timeout'],
                threads=MONITOR_CONFIG['threads']
            )
            
            self._last_test_time = datetime.now()
            self._test_count += 1
            
            logger.info(f"Test cycle completed: {len(results)} results")
            
            # Notify callbacks
            self._notify_callbacks(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Test cycle failed: {e}")
            return []
    
    def _cleanup_cycle(self):
        """Cleanup old data periodically"""
        try:
            deleted = db.cleanup_old_data(RETENTION_DAYS)
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} old test records")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        cleanup_counter = 0
        
        while not self._stop_event.is_set():
            self._test_cycle()
            
            # Cleanup every 24 cycles (approximately daily if interval is 1 hour)
            cleanup_counter += 1
            if cleanup_counter >= 24:
                self._cleanup_cycle()
                cleanup_counter = 0
            
            # Wait for next cycle or stop event
            self._stop_event.wait(self.interval)
    
    def start(self, run_immediately: bool = True):
        """Start the periodic monitor"""
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
    
    def stop(self, timeout: float = 10.0):
        """Stop the periodic monitor"""
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
        """Check if monitor is running"""
        return self._is_running
    
    def get_status(self) -> dict:
        """Get monitor status"""
        return {
            "is_running": self._is_running,
            "interval_seconds": self.interval,
            "last_test_time": self._last_test_time.isoformat() if self._last_test_time else None,
            "test_count": self._test_count,
            "next_test_in": self._calculate_next_test()
        }
    
    def _calculate_next_test(self) -> Optional[int]:
        """Calculate seconds until next test"""
        if not self._is_running or not self._last_test_time:
            return None
        
        elapsed = (datetime.now() - self._last_test_time).total_seconds()
        remaining = max(0, self.interval - elapsed)
        return int(remaining)
    
    def set_interval(self, seconds: int):
        """Change test interval"""
        self.interval = max(30, seconds)  # Minimum 30 seconds
        logger.info(f"Monitor interval changed to {self.interval}s")
    
    def trigger_immediate_test(self) -> List:
        """Trigger an immediate test cycle"""
        return self._test_cycle()


class MonitorDaemon:
    """
    Daemon wrapper for running monitor as background service
    Handles signals and graceful shutdown
    """
    
    def __init__(self, interval_seconds: int = None):
        self.monitor = PeriodicMonitor(interval_seconds)
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            self.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def run(self, run_initial_scan_first: bool = False):
        """Run the monitor daemon"""
        logger.info("Starting Cloudflare IP Monitor Daemon...")
        
        if run_initial_scan_first:
            logger.info("Running initial scan...")
            results, metadata = run_initial_scan()
            logger.info(f"Initial scan complete: {metadata}")
        
        self.monitor.start(run_immediately=True)
        
        # Keep main thread alive
        try:
            while self.monitor.is_running():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
    
    def stop(self):
        """Stop the daemon"""
        self.monitor.stop()


# Global monitor instance
monitor = PeriodicMonitor()


def start_monitoring(interval_seconds: int = None, run_immediately: bool = True):
    """Start periodic monitoring"""
    global monitor
    if interval_seconds:
        monitor.set_interval(interval_seconds)
    monitor.start(run_immediately)


def stop_monitoring():
    """Stop periodic monitoring"""
    monitor.stop()


def get_monitor_status() -> dict:
    """Get current monitor status"""
    return monitor.get_status()


if __name__ == "__main__":
    # Run as standalone daemon
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    daemon = MonitorDaemon()
    daemon.run(run_initial_scan_first=True)
