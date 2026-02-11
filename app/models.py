from datetime import datetime, timezone

from app.extensions import db


def _utc_iso(dt):
    """Return ISO format string with Z suffix for UTC datetimes."""
    if dt is None:
        return None
    s = dt.isoformat()
    if not s.endswith("Z") and "+" not in s:
        s += "Z"
    return s


class IP(db.Model):
    __tablename__ = "ips"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_tested = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True, index=True)
    total_tests = db.Column(db.Integer, default=0)
    avg_latency = db.Column(db.Float)
    avg_download_speed = db.Column(db.Float)
    avg_upload_speed = db.Column(db.Float)
    avg_loss_rate = db.Column(db.Float)
    best_latency = db.Column(db.Float)
    best_download_speed = db.Column(db.Float)
    worst_latency = db.Column(db.Float)
    worst_download_speed = db.Column(db.Float)
    colo_code = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    test_results = db.relationship(
        "TestResult", backref="ip", lazy="dynamic", cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "first_seen": _utc_iso(self.first_seen),
            "last_tested": _utc_iso(self.last_tested),
            "is_active": self.is_active,
            "total_tests": self.total_tests,
            "avg_latency": self.avg_latency,
            "avg_download_speed": self.avg_download_speed,
            "avg_upload_speed": self.avg_upload_speed,
            "avg_loss_rate": self.avg_loss_rate,
            "best_latency": self.best_latency,
            "best_download_speed": self.best_download_speed,
            "worst_latency": self.worst_latency,
            "worst_download_speed": self.worst_download_speed,
            "colo_code": self.colo_code,
            "created_at": _utc_iso(self.created_at),
        }


class TestResult(db.Model):
    __tablename__ = "test_results"

    id = db.Column(db.Integer, primary_key=True)
    ip_id = db.Column(
        db.Integer,
        db.ForeignKey("ips.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    test_time = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )
    latency_ms = db.Column(db.Float)
    download_speed_mbps = db.Column(db.Float)
    upload_speed_mbps = db.Column(db.Float)
    loss_rate = db.Column(db.Float)
    packets_sent = db.Column(db.Integer)
    packets_received = db.Column(db.Integer)
    colo_code = db.Column(db.String(10))
    test_type = db.Column(db.String(20), default="periodic")

    def to_dict(self):
        return {
            "id": self.id,
            "ip_id": self.ip_id,
            "test_time": _utc_iso(self.test_time),
            "latency_ms": self.latency_ms,
            "download_speed_mbps": self.download_speed_mbps,
            "upload_speed_mbps": self.upload_speed_mbps,
            "loss_rate": self.loss_rate,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "colo_code": self.colo_code,
            "test_type": self.test_type,
        }


class ScanSession(db.Model):
    __tablename__ = "scan_sessions"

    id = db.Column(db.Integer, primary_key=True)
    scan_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    total_ips_tested = db.Column(db.Integer)
    ips_passed = db.Column(db.Integer)
    min_speed_threshold = db.Column(db.Float)
    max_latency_threshold = db.Column(db.Float)
    max_loss_threshold = db.Column(db.Float)
    scan_duration_seconds = db.Column(db.Float)
    status = db.Column(db.String(20), default="completed")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_time": _utc_iso(self.scan_time),
            "total_ips_tested": self.total_ips_tested,
            "ips_passed": self.ips_passed,
            "min_speed_threshold": self.min_speed_threshold,
            "max_latency_threshold": self.max_latency_threshold,
            "max_loss_threshold": self.max_loss_threshold,
            "scan_duration_seconds": self.scan_duration_seconds,
            "status": self.status,
        }
