import logging
import threading
from datetime import date, datetime, timedelta, timezone

from flask import current_app, jsonify, request
from sqlalchemy import func

from app.api import api_bp
from app.extensions import db
from app.models import IP, ScanSession, TestResult

logger = logging.getLogger(__name__)

VALID_SORT_COLUMNS = {
    "ip_address",
    "avg_latency",
    "avg_download_speed",
    "avg_loss_rate",
    "total_tests",
    "last_tested",
    "best_latency",
    "best_download_speed",
}


@api_bp.route("/stats")
def get_stats():
    total_active = IP.query.filter_by(is_active=True).count()
    total_tests = TestResult.query.count()
    tests_today = TestResult.query.filter(
        TestResult.test_time >= datetime.combine(date.today(), datetime.min.time())
    ).count()

    row = db.session.query(
        func.avg(IP.avg_latency),
        func.avg(IP.avg_download_speed),
        func.avg(IP.avg_loss_rate),
        func.min(IP.best_latency),
        func.max(IP.best_download_speed),
    ).filter(IP.is_active == True).first()  # noqa: E712

    top_ips = (
        IP.query.filter_by(is_active=True)
        .order_by(IP.avg_download_speed.desc())
        .limit(5)
        .all()
    )

    recent_scans = (
        ScanSession.query.order_by(ScanSession.scan_time.desc()).limit(5).all()
    )

    stats = {
        "total_active_ips": total_active,
        "total_tests": total_tests,
        "tests_today": tests_today,
        "avg_latency": round(row[0] or 0, 2),
        "avg_speed": round(row[1] or 0, 2),
        "avg_loss": round(row[2] or 0, 4),
        "best_latency": round(row[3] or 0, 2),
        "best_speed": round(row[4] or 0, 2),
        "top_ips": [ip.to_dict() for ip in top_ips],
        "recent_scans": [s.to_dict() for s in recent_scans],
        "monitor": current_app.monitor.get_status(),
    }
    return jsonify(stats)


@api_bp.route("/ips")
def get_ips():
    order_by = request.args.get("sort", "avg_download_speed")
    order_dir = request.args.get("dir", "DESC").upper()
    search = request.args.get("search")
    active_only = request.args.get("active", "true").lower() == "true"

    query = IP.query
    if active_only:
        query = query.filter_by(is_active=True)
    if search:
        query = query.filter(IP.ip_address.like(f"%{search}%"))

    if order_by in VALID_SORT_COLUMNS:
        col = getattr(IP, order_by)
        query = query.order_by(col.desc() if order_dir == "DESC" else col.asc())

    ips = query.all()
    result = [ip.to_dict() for ip in ips]
    return jsonify({"ips": result, "total": len(result)})


@api_bp.route("/ip")
def get_ip_detail():
    ip_address = request.args.get("ip")
    if not ip_address:
        return jsonify({"error": "IP required"}), 400

    ip = IP.query.filter_by(ip_address=ip_address).first()
    if not ip:
        return jsonify({"error": "IP not found"}), 404

    return jsonify(ip.to_dict())


@api_bp.route("/history")
def get_history():
    ip_address = request.args.get("ip")
    hours = int(request.args.get("hours", 24))
    if not ip_address:
        return jsonify({"error": "IP required"}), 400

    ip = IP.query.filter_by(ip_address=ip_address).first()
    if not ip:
        return jsonify({"ip": ip_address, "history": []})

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    results = (
        TestResult.query.filter(
            TestResult.ip_id == ip.id, TestResult.test_time >= cutoff
        )
        .order_by(TestResult.test_time.desc())
        .all()
    )
    return jsonify({"ip": ip_address, "history": [r.to_dict() for r in results]})


@api_bp.route("/hourly")
def get_hourly():
    hours = int(request.args.get("hours", 24))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    stats = (
        db.session.query(
            func.strftime("%Y-%m-%d %H:00", TestResult.test_time).label("hour"),
            func.count().label("test_count"),
            func.avg(TestResult.latency_ms).label("avg_latency"),
            func.avg(TestResult.download_speed_mbps).label("avg_speed"),
            func.avg(TestResult.loss_rate).label("avg_loss"),
        )
        .filter(TestResult.test_time >= cutoff)
        .group_by("hour")
        .order_by("hour")
        .all()
    )

    result = [
        {
            "hour": s.hour,
            "test_count": s.test_count,
            "avg_latency": round(s.avg_latency or 0, 2),
            "avg_speed": round(s.avg_speed or 0, 2),
            "avg_loss": round(s.avg_loss or 0, 4),
        }
        for s in stats
    ]
    return jsonify({"hours": hours, "stats": result})


@api_bp.route("/monitor/status")
def monitor_status():
    return jsonify(current_app.monitor.get_status())


@api_bp.route("/scan/initial", methods=["POST"])
def start_initial_scan():
    data = request.get_json(silent=True) or {}
    app = current_app._get_current_object()

    def run_scan():
        results, metadata = app.scanner.initial_scan(
            min_speed=data.get("min_speed", 10.0),
            max_loss=data.get("max_loss", 0.25),
            max_latency=data.get("max_latency", 1000),
            test_count=data.get("test_count", 50),
        )
        logger.info(f"Initial scan completed: {metadata}")

    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"status": "started", "message": "Initial scan started in background"})


@api_bp.route("/scan/test", methods=["POST"])
def test_now():
    app = current_app._get_current_object()

    def run_test():
        results = app.monitor.trigger_immediate_test()
        logger.info(f"Immediate test completed: {len(results)} results")

    threading.Thread(target=run_test, daemon=True).start()
    return jsonify({"status": "started", "message": "Test started"})


@api_bp.route("/monitor/start", methods=["POST"])
def start_monitor():
    data = request.get_json(silent=True) or {}
    interval = data.get("interval", 120)
    current_app.monitor.set_interval(interval)
    current_app.monitor.start(run_immediately=True)
    return jsonify({"status": "started", "interval": interval})


@api_bp.route("/monitor/stop", methods=["POST"])
def stop_monitor():
    current_app.monitor.stop()
    return jsonify({"status": "stopped"})


@api_bp.route("/monitor/interval", methods=["POST"])
def set_interval():
    data = request.get_json(silent=True) or {}
    interval = data.get("interval", 120)
    current_app.monitor.set_interval(interval)
    return jsonify({"status": "updated", "interval": interval})


@api_bp.route("/ip/deactivate", methods=["POST"])
def deactivate_ip():
    data = request.get_json(silent=True) or {}
    ip_address = data.get("ip")
    if not ip_address:
        return jsonify({"error": "IP required"}), 400

    ip = IP.query.filter_by(ip_address=ip_address).first()
    if ip:
        ip.is_active = False
        db.session.commit()

    return jsonify({"status": "deactivated", "ip": ip_address})
