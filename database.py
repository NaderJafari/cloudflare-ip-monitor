#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare IP Monitor - Database Module
SQLite database for storing IP test results and historical data
"""

import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from contextlib import contextmanager

from config import DATABASE_PATH, RETENTION_DAYS


class Database:
    """Thread-safe SQLite database handler for Cloudflare IP monitoring"""
    
    _local = threading.local()
    
    def __init__(self, db_path: Path = DATABASE_PATH):
        self.db_path = db_path
        self._init_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                timeout=30.0
            )
            self._local.connection.row_factory = sqlite3.Row
            self._local.connection.execute("PRAGMA journal_mode=WAL")
            self._local.connection.execute("PRAGMA synchronous=NORMAL")
        return self._local.connection
    
    @contextmanager
    def get_cursor(self):
        """Context manager for database cursor"""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
    
    def _init_database(self):
        """Initialize database schema"""
        with self.get_cursor() as cursor:
            # Main IP table - stores discovered IPs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_tested TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    total_tests INTEGER DEFAULT 0,
                    avg_latency REAL,
                    avg_download_speed REAL,
                    avg_upload_speed REAL,
                    avg_loss_rate REAL,
                    best_latency REAL,
                    best_download_speed REAL,
                    worst_latency REAL,
                    worst_download_speed REAL,
                    colo_code TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Historical test results - stores each test
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_id INTEGER NOT NULL,
                    test_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    latency_ms REAL,
                    download_speed_mbps REAL,
                    upload_speed_mbps REAL,
                    loss_rate REAL,
                    packets_sent INTEGER,
                    packets_received INTEGER,
                    colo_code TEXT,
                    test_type TEXT DEFAULT 'periodic',
                    FOREIGN KEY (ip_id) REFERENCES ips(id) ON DELETE CASCADE
                )
            """)
            
            # Initial scan results - stores initial discovery scans
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_ips_tested INTEGER,
                    ips_passed INTEGER,
                    min_speed_threshold REAL,
                    max_latency_threshold REAL,
                    max_loss_threshold REAL,
                    scan_duration_seconds REAL,
                    status TEXT DEFAULT 'completed'
                )
            """)
            
            # Create indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_test_results_ip_id ON test_results(ip_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_test_results_time ON test_results(test_time)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ips_address ON ips(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ips_active ON ips(is_active)")
    
    def add_or_update_ip(self, ip_address: str, **kwargs) -> int:
        """Add new IP or update existing one, returns IP id"""
        with self.get_cursor() as cursor:
            cursor.execute("SELECT id FROM ips WHERE ip_address = ?", (ip_address,))
            row = cursor.fetchone()
            
            if row:
                ip_id = row['id']
                if kwargs:
                    set_clause = ", ".join([f"{k} = ?" for k in kwargs.keys()])
                    cursor.execute(
                        f"UPDATE ips SET {set_clause}, last_tested = CURRENT_TIMESTAMP WHERE id = ?",
                        (*kwargs.values(), ip_id)
                    )
            else:
                columns = ['ip_address'] + list(kwargs.keys())
                placeholders = ', '.join(['?' for _ in columns])
                cursor.execute(
                    f"INSERT INTO ips ({', '.join(columns)}) VALUES ({placeholders})",
                    (ip_address, *kwargs.values())
                )
                ip_id = cursor.lastrowid
            
            return ip_id
    
    def add_test_result(self, ip_address: str, latency_ms: float, download_speed: float,
                        loss_rate: float, packets_sent: int = 4, packets_received: int = 4,
                        upload_speed: float = None, colo_code: str = None,
                        test_type: str = 'periodic') -> int:
        """Add a test result and update IP statistics"""
        
        # Get or create IP
        ip_id = self.add_or_update_ip(ip_address, colo_code=colo_code)
        
        with self.get_cursor() as cursor:
            # Insert test result
            cursor.execute("""
                INSERT INTO test_results 
                (ip_id, latency_ms, download_speed_mbps, upload_speed_mbps, loss_rate, 
                 packets_sent, packets_received, colo_code, test_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ip_id, latency_ms, download_speed, upload_speed, loss_rate,
                  packets_sent, packets_received, colo_code, test_type))
            
            result_id = cursor.lastrowid
            
            # Update IP statistics
            cursor.execute("""
                UPDATE ips SET
                    last_tested = CURRENT_TIMESTAMP,
                    total_tests = total_tests + 1,
                    avg_latency = (
                        SELECT AVG(latency_ms) FROM test_results WHERE ip_id = ?
                    ),
                    avg_download_speed = (
                        SELECT AVG(download_speed_mbps) FROM test_results WHERE ip_id = ?
                    ),
                    avg_loss_rate = (
                        SELECT AVG(loss_rate) FROM test_results WHERE ip_id = ?
                    ),
                    best_latency = (
                        SELECT MIN(latency_ms) FROM test_results WHERE ip_id = ?
                    ),
                    best_download_speed = (
                        SELECT MAX(download_speed_mbps) FROM test_results WHERE ip_id = ?
                    ),
                    worst_latency = (
                        SELECT MAX(latency_ms) FROM test_results WHERE ip_id = ?
                    ),
                    worst_download_speed = (
                        SELECT MIN(download_speed_mbps) FROM test_results WHERE ip_id = ?
                    )
                WHERE id = ?
            """, (ip_id, ip_id, ip_id, ip_id, ip_id, ip_id, ip_id, ip_id))
            
            return result_id
    
    def add_scan_session(self, total_tested: int, passed: int, min_speed: float,
                         max_latency: float, max_loss: float, duration: float) -> int:
        """Record a scan session"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO scan_sessions 
                (total_ips_tested, ips_passed, min_speed_threshold, max_latency_threshold,
                 max_loss_threshold, scan_duration_seconds)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (total_tested, passed, min_speed, max_latency, max_loss, duration))
            return cursor.lastrowid
    
    def get_active_ips(self, limit: int = None) -> List[Dict]:
        """Get all active IPs for periodic testing"""
        with self.get_cursor() as cursor:
            query = """
                SELECT * FROM ips 
                WHERE is_active = 1 
                ORDER BY avg_download_speed DESC, avg_latency ASC
            """
            if limit:
                query += f" LIMIT {limit}"
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_ip_history(self, ip_address: str, hours: int = 24) -> List[Dict]:
        """Get test history for a specific IP"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT tr.* FROM test_results tr
                JOIN ips i ON tr.ip_id = i.id
                WHERE i.ip_address = ?
                AND tr.test_time >= datetime('now', ?)
                ORDER BY tr.test_time DESC
            """, (ip_address, f'-{hours} hours'))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_all_ips_with_stats(self, order_by: str = 'avg_download_speed',
                                order_dir: str = 'DESC',
                                search: str = None,
                                active_only: bool = True) -> List[Dict]:
        """Get all IPs with their statistics"""
        with self.get_cursor() as cursor:
            query = "SELECT * FROM ips WHERE 1=1"
            params = []
            
            if active_only:
                query += " AND is_active = 1"
            
            if search:
                query += " AND ip_address LIKE ?"
                params.append(f"%{search}%")
            
            # Validate order_by to prevent SQL injection
            valid_columns = ['ip_address', 'avg_latency', 'avg_download_speed', 
                           'avg_loss_rate', 'total_tests', 'last_tested', 
                           'best_latency', 'best_download_speed']
            if order_by in valid_columns:
                query += f" ORDER BY {order_by} {order_dir}"
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict:
        """Get overall statistics"""
        with self.get_cursor() as cursor:
            stats = {}
            
            # Total IPs
            cursor.execute("SELECT COUNT(*) as count FROM ips WHERE is_active = 1")
            stats['total_active_ips'] = cursor.fetchone()['count']
            
            # Total tests
            cursor.execute("SELECT COUNT(*) as count FROM test_results")
            stats['total_tests'] = cursor.fetchone()['count']
            
            # Tests today
            cursor.execute("""
                SELECT COUNT(*) as count FROM test_results 
                WHERE test_time >= date('now')
            """)
            stats['tests_today'] = cursor.fetchone()['count']
            
            # Average metrics
            cursor.execute("""
                SELECT 
                    AVG(avg_latency) as avg_latency,
                    AVG(avg_download_speed) as avg_speed,
                    AVG(avg_loss_rate) as avg_loss,
                    MIN(best_latency) as best_latency,
                    MAX(best_download_speed) as best_speed
                FROM ips WHERE is_active = 1
            """)
            row = cursor.fetchone()
            stats['avg_latency'] = round(row['avg_latency'] or 0, 2)
            stats['avg_speed'] = round(row['avg_speed'] or 0, 2)
            stats['avg_loss'] = round(row['avg_loss'] or 0, 4)
            stats['best_latency'] = round(row['best_latency'] or 0, 2)
            stats['best_speed'] = round(row['best_speed'] or 0, 2)
            
            # Top 5 IPs by speed
            cursor.execute("""
                SELECT ip_address, avg_download_speed, avg_latency, avg_loss_rate
                FROM ips WHERE is_active = 1
                ORDER BY avg_download_speed DESC LIMIT 5
            """)
            stats['top_ips'] = [dict(row) for row in cursor.fetchall()]
            
            # Recent scan sessions
            cursor.execute("""
                SELECT * FROM scan_sessions ORDER BY scan_time DESC LIMIT 5
            """)
            stats['recent_scans'] = [dict(row) for row in cursor.fetchall()]
            
            return stats
    
    def get_hourly_stats(self, hours: int = 24) -> List[Dict]:
        """Get hourly aggregated statistics"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT 
                    strftime('%Y-%m-%d %H:00', test_time) as hour,
                    COUNT(*) as test_count,
                    AVG(latency_ms) as avg_latency,
                    AVG(download_speed_mbps) as avg_speed,
                    AVG(loss_rate) as avg_loss
                FROM test_results
                WHERE test_time >= datetime('now', ?)
                GROUP BY strftime('%Y-%m-%d %H:00', test_time)
                ORDER BY hour
            """, (f'-{hours} hours',))
            return [dict(row) for row in cursor.fetchall()]
    
    def cleanup_old_data(self, days: int = RETENTION_DAYS):
        """Remove old test results to save space"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                DELETE FROM test_results 
                WHERE test_time < datetime('now', ?)
            """, (f'-{days} days',))
            deleted = cursor.rowcount
            
            # Vacuum to reclaim space
            self._get_connection().execute("VACUUM")
            
            return deleted
    
    def deactivate_ip(self, ip_address: str):
        """Mark IP as inactive"""
        with self.get_cursor() as cursor:
            cursor.execute(
                "UPDATE ips SET is_active = 0 WHERE ip_address = ?",
                (ip_address,)
            )
    
    def get_ip_details(self, ip_address: str) -> Optional[Dict]:
        """Get detailed information for a specific IP"""
        with self.get_cursor() as cursor:
            cursor.execute("SELECT * FROM ips WHERE ip_address = ?", (ip_address,))
            row = cursor.fetchone()
            return dict(row) if row else None


# Singleton instance
db = Database()
