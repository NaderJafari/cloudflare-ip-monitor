import logging
from datetime import datetime, timezone

from sqlalchemy import func, text

from app.extensions import db
from app.models import IP, TestResult, ScanSession

logger = logging.getLogger(__name__)


def add_test_result(
    ip_address,
    latency_ms,
    download_speed,
    loss_rate,
    packets_sent=4,
    packets_received=4,
    upload_speed=None,
    colo_code=None,
    test_type="periodic",
):
    """Add a test result and update IP aggregate statistics."""
    ip = IP.query.filter_by(ip_address=ip_address).first()
    if not ip:
        ip = IP(ip_address=ip_address, colo_code=colo_code)
        db.session.add(ip)
        db.session.flush()
    elif colo_code:
        ip.colo_code = colo_code
        ip.last_tested = datetime.now(timezone.utc)

    result = TestResult(
        ip_id=ip.id,
        latency_ms=latency_ms,
        download_speed_mbps=download_speed,
        upload_speed_mbps=upload_speed,
        loss_rate=loss_rate,
        packets_sent=packets_sent,
        packets_received=packets_received,
        colo_code=colo_code,
        test_type=test_type,
    )
    db.session.add(result)
    db.session.flush()

    # Update IP aggregate statistics
    stats = db.session.query(
        func.avg(TestResult.latency_ms),
        func.avg(TestResult.download_speed_mbps),
        func.avg(TestResult.loss_rate),
        func.min(TestResult.latency_ms),
        func.max(TestResult.download_speed_mbps),
        func.max(TestResult.latency_ms),
        func.min(TestResult.download_speed_mbps),
    ).filter(TestResult.ip_id == ip.id).first()

    ip.avg_latency = stats[0]
    ip.avg_download_speed = stats[1]
    ip.avg_loss_rate = stats[2]
    ip.best_latency = stats[3]
    ip.best_download_speed = stats[4]
    ip.worst_latency = stats[5]
    ip.worst_download_speed = stats[6]
    ip.total_tests = (ip.total_tests or 0) + 1
    ip.last_tested = datetime.now(timezone.utc)

    db.session.commit()
    return result.id


def add_scan_session(total_tested, passed, min_speed, max_latency, max_loss, duration):
    """Record a completed scan session."""
    session = ScanSession(
        total_ips_tested=total_tested,
        ips_passed=passed,
        min_speed_threshold=min_speed,
        max_latency_threshold=max_latency,
        max_loss_threshold=max_loss,
        scan_duration_seconds=duration,
    )
    db.session.add(session)
    db.session.commit()
    return session.id


def get_active_ips(limit=None):
    """Get active IPs ordered by speed then latency."""
    query = (
        IP.query.filter_by(is_active=True)
        .order_by(IP.avg_download_speed.desc(), IP.avg_latency.asc())
    )
    if limit:
        query = query.limit(limit)
    return [ip.to_dict() for ip in query.all()]


def cleanup_old_data(retention_days):
    """Remove test results older than retention period."""
    cutoff = text(f"datetime('now', '-{int(retention_days)} days')")
    deleted = TestResult.query.filter(TestResult.test_time < cutoff).delete(
        synchronize_session=False
    )
    db.session.commit()

    if deleted > 0:
        db.session.execute(text("VACUUM"))
        logger.info(f"Cleaned up {deleted} old test records")

    return deleted
