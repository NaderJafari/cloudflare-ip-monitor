#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare IP Monitor - Scanner Module
Wrapper for CloudflareScanner binary to perform IP scanning and testing
"""

import subprocess
import csv
import tempfile
import logging
import time
import os
import stat
import urllib.request
import zipfile
import platform
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

from config import (
    SCANNER_BINARY, SCANNER_DIR, INITIAL_SCAN_CONFIG, MONITOR_CONFIG,
    CLOUDFLARE_IPV4_RANGES, CLOUDFLARE_IPV6_RANGES, DATA_DIR
)
from database import db

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Represents a single IP scan result"""
    ip_address: str
    packets_sent: int
    packets_received: int
    loss_rate: float
    latency_ms: float
    download_speed: float  # MB/s
    colo_code: Optional[str] = None


class CloudflareScanner:
    """Wrapper for CloudflareScanner binary"""
    
    RELEASES_URL = "https://github.com/bia-pain-bache/Cloudflare-Clean-IP-Scanner/releases/download/v2.2.5"
    
    def __init__(self):
        self.binary_path = SCANNER_BINARY
        self._ensure_binary()
    
    def _get_platform_suffix(self) -> str:
        """Get the appropriate binary suffix for current platform"""
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        if system == "linux":
            if machine in ("x86_64", "amd64"):
                return "linux-amd64"
            elif machine in ("aarch64", "arm64"):
                return "linux-arm64"
            elif machine.startswith("arm"):
                return "linux-arm7"
        elif system == "darwin":
            if machine in ("arm64", "aarch64"):
                return "darwin-arm64"
            else:
                return "darwin-amd64"
        elif system == "windows":
            if machine in ("amd64", "x86_64"):
                return "windows-amd64"
            else:
                return "windows-386"
        
        # Default to linux-amd64
        return "linux-amd64"
    
    def _ensure_binary(self):
        """Ensure CloudflareScanner binary exists and is executable"""
        SCANNER_DIR.mkdir(parents=True, exist_ok=True)
        
        if not self.binary_path.exists():
            logger.info("CloudflareScanner binary not found, downloading...")
            self._download_binary()
        
        # Ensure executable
        if os.name != 'nt':  # Not Windows
            st = os.stat(self.binary_path)
            os.chmod(self.binary_path, st.st_mode | stat.S_IEXEC)
    
    def _download_binary(self):
        """Download CloudflareScanner binary from GitHub releases"""
        suffix = self._get_platform_suffix()
        filename = f"CloudflareScanner_{suffix}.zip"
        url = f"{self.RELEASES_URL}/{filename}"
        
        zip_path = SCANNER_DIR / filename
        
        logger.info(f"Downloading {url}...")
        try:
            urllib.request.urlretrieve(url, zip_path)
            
            # Extract
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(SCANNER_DIR)
            
            # Remove zip
            zip_path.unlink()
            
            # Find the binary (might be CloudflareScanner or CloudflareScanner.exe)
            for f in SCANNER_DIR.iterdir():
                if f.name.startswith("CloudflareScanner") and f.is_file():
                    if f != self.binary_path:
                        f.rename(self.binary_path)
                    break
            
            logger.info("CloudflareScanner binary downloaded successfully")
        except Exception as e:
            logger.error(f"Failed to download CloudflareScanner: {e}")
            raise RuntimeError(
                f"Failed to download CloudflareScanner. Please download manually from "
                f"{self.RELEASES_URL} and place in {SCANNER_DIR}"
            )
    
    def _create_ip_file(self, ip_ranges: List[str] = None) -> Path:
        """Create temporary file with IP ranges to scan"""
        if ip_ranges is None:
            ip_ranges = CLOUDFLARE_IPV4_RANGES + CLOUDFLARE_IPV6_RANGES
        
        ip_file = DATA_DIR / "scan_ips.txt"
        with open(ip_file, 'w') as f:
            f.write('\n'.join(ip_ranges))
        return ip_file
    
    def _parse_results(self, result_file: Path) -> List[ScanResult]:
        """Parse CSV results from CloudflareScanner"""
        results = []
        
        if not result_file.exists():
            logger.warning(f"Result file not found: {result_file}")
            return results
        
        try:
            with open(result_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Skip header if present
                content = f.read()
                lines = content.strip().split('\n')
                
                for line in lines:
                    # Skip header line
                    if 'IP' in line and 'Latency' in line:
                        continue
                    
                    parts = line.split(',')
                    if len(parts) >= 6:
                        try:
                            result = ScanResult(
                                ip_address=parts[0].strip(),
                                packets_sent=int(parts[1].strip()),
                                packets_received=int(parts[2].strip()),
                                loss_rate=float(parts[3].strip()),
                                latency_ms=float(parts[4].strip()),
                                download_speed=float(parts[5].strip())
                            )
                            results.append(result)
                        except (ValueError, IndexError) as e:
                            logger.debug(f"Failed to parse line: {line}, error: {e}")
                            continue
        except Exception as e:
            logger.error(f"Failed to read result file: {e}")
        
        return results
    
    def initial_scan(self, ip_ranges: List[str] = None,
                     min_speed: float = None,
                     max_loss: float = None,
                     max_latency: float = None,
                     test_count: int = None,
                     threads: int = None) -> Tuple[List[ScanResult], Dict]:
        """
        Perform initial scan of all Cloudflare IPs to find good ones
        
        Args:
            ip_ranges: List of CIDR ranges to scan
            min_speed: Minimum download speed in MB/s
            max_loss: Maximum loss rate (0-1)
            max_latency: Maximum latency in ms
            test_count: Number of IPs to download test
            threads: Concurrent threads
        
        Returns:
            Tuple of (list of results, scan metadata)
        """
        config = INITIAL_SCAN_CONFIG.copy()
        if min_speed is not None:
            config['min_speed'] = min_speed
        if max_loss is not None:
            config['max_loss_rate'] = max_loss
        if max_latency is not None:
            config['max_latency'] = max_latency
        if test_count is not None:
            config['test_count'] = test_count
        if threads is not None:
            config['threads'] = threads
        
        ip_file = self._create_ip_file(ip_ranges)
        result_file = DATA_DIR / "initial_scan_result.csv"
        
        # Build command
        cmd = [
            str(self.binary_path),
            "-f", str(ip_file),
            "-o", str(result_file),
            "-n", str(config['threads']),
            "-url", str(config['url']),
            "-t", str(config['ping_times']),
            "-dn", str(config['test_count']),
            "-dt", str(config['download_timeout']),
            "-tp", str(config['port']),
            "-tl", str(config['max_latency']),
            "-tlr", str(config['max_loss_rate']),
            "-sl", str(config['min_speed']),
            "-p", "0",  # Don't print to console
        ]
        
        logger.info(f"Starting initial scan with command: {' '.join(cmd)}")
        
        start_time = time.time()
        
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour timeout
                cwd=str(SCANNER_DIR)
            )
            
            if process.returncode != 0:
                logger.warning(f"Scanner returned non-zero: {process.stderr}")
        except subprocess.TimeoutExpired:
            logger.error("Initial scan timed out after 1 hour")
            return [], {"error": "timeout"}
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return [], {"error": str(e)}
        
        duration = time.time() - start_time
        results = self._parse_results(result_file)
        
        # Filter results based on criteria
        filtered_results = [
            r for r in results
            if r.download_speed >= config['min_speed']
            and r.loss_rate <= config['max_loss_rate']
            and r.latency_ms <= config['max_latency']
        ]
        
        # Store results in database
        for result in filtered_results:
            db.add_test_result(
                ip_address=result.ip_address,
                latency_ms=result.latency_ms,
                download_speed=result.download_speed,
                loss_rate=result.loss_rate,
                packets_sent=result.packets_sent,
                packets_received=result.packets_received,
                test_type='initial_scan'
            )
        
        # Record scan session
        scan_id = db.add_scan_session(
            total_tested=len(results),
            passed=len(filtered_results),
            min_speed=config['min_speed'],
            max_latency=config['max_latency'],
            max_loss=config['max_loss_rate'],
            duration=duration
        )
        
        metadata = {
            "scan_id": scan_id,
            "total_tested": len(results),
            "passed": len(filtered_results),
            "duration_seconds": round(duration, 2),
            "config": config
        }
        
        logger.info(f"Initial scan completed: {len(filtered_results)} IPs passed out of {len(results)}")
        
        return filtered_results, metadata
    
    def test_specific_ips(self, ip_addresses: List[str],
                          timeout: int = None,
                          threads: int = None) -> List[ScanResult]:
        """
        Test specific IPs for periodic monitoring
        
        Args:
            ip_addresses: List of IP addresses to test
            timeout: Download test timeout
            threads: Concurrent threads
        
        Returns:
            List of scan results
        """
        if not ip_addresses:
            return []
        
        config = MONITOR_CONFIG.copy()
        if timeout is not None:
            config['download_timeout'] = timeout
        if threads is not None:
            config['threads'] = threads
        
        # Create temp file with IPs to test
        ip_file = DATA_DIR / "monitor_ips.txt"
        with open(ip_file, 'w') as f:
            # Write each IP as /32 for single IP testing
            for ip in ip_addresses:
                if ':' in ip:  # IPv6
                    f.write(f"{ip}/128\n")
                else:  # IPv4
                    f.write(f"{ip}/32\n")
        
        result_file = DATA_DIR / "monitor_result.csv"
        
        # Build command - test all IPs (not random sampling)
        cmd = [
            str(self.binary_path),
            "-f", str(ip_file),
            "-o", str(result_file),
            "-n", str(min(config['threads'], len(ip_addresses))),
            "-t", str(config['ping_times']),
            "-dn", str(len(ip_addresses)),  # Test all
            "-dt", str(config['download_timeout']),
            "-url", str(config['url']),
            "-tp", str(config['port']),
            "-allip",  # Test all IPs, not random sample
            "-p", "0",
        ]
        
        logger.debug(f"Testing {len(ip_addresses)} IPs...")
        
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=str(SCANNER_DIR)
            )
        except subprocess.TimeoutExpired:
            logger.warning("Periodic test timed out")
            return []
        except Exception as e:
            logger.error(f"Test failed: {e}")
            return []
        
        results = self._parse_results(result_file)
        
        # Store results in database
        for result in results:
            db.add_test_result(
                ip_address=result.ip_address,
                latency_ms=result.latency_ms,
                download_speed=result.download_speed,
                loss_rate=result.loss_rate,
                packets_sent=result.packets_sent,
                packets_received=result.packets_received,
                test_type='periodic'
            )
        
        return results


# Singleton instance
scanner = CloudflareScanner()


def run_initial_scan(**kwargs) -> Tuple[List[ScanResult], Dict]:
    """Convenience function to run initial scan"""
    return scanner.initial_scan(**kwargs)


def run_periodic_test(ip_addresses: List[str] = None, **kwargs) -> List[ScanResult]:
    """Convenience function to run periodic test on active IPs"""
    if ip_addresses is None:
        # Get active IPs from database
        active_ips = db.get_active_ips(limit=kwargs.get('max_ips', MONITOR_CONFIG['max_ips_per_cycle']))
        ip_addresses = [ip['ip_address'] for ip in active_ips]
    
    return scanner.test_specific_ips(ip_addresses, **kwargs)
