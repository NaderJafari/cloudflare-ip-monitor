import logging
import threading
from datetime import date, datetime, timedelta, timezone
from functools import wraps

from flask import current_app, jsonify, request, session

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
    "smart_score",
}


def login_required_api(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def compute_smart_score(ip_dict, max_speed, max_latency, reliable_tests=5):
    """Compute a composite quality score for an IP.

    Weights: speed 40%, latency 35%, loss rate 25%.
    Test reliability acts as a multiplier: IPs with fewer tests than
    `reliable_tests` get their score dampened significantly so that
    recently-added IPs don't dominate just because of one fast result.
    """
    speed = ip_dict.get("avg_download_speed") or 0
    latency = ip_dict.get("avg_latency") or 9999
    loss = ip_dict.get("avg_loss_rate") or 1
    tests = ip_dict.get("total_tests") or 0

    speed_norm = (speed / max_speed) if max_speed > 0 else 0
    latency_norm = max(0, 1 - (latency / max_latency)) if max_latency > 0 else 0
    loss_norm = max(0, 1 - loss)

    raw_score = (speed_norm * 0.40) + (latency_norm * 0.35) + (loss_norm * 0.25)

    # Dampen score for IPs with few tests (min 50% of raw score)
    test_reliability = min(tests / reliable_tests, 1.0)
    return raw_score * (0.5 + 0.5 * test_reliability)


@api_bp.route("/stats")
@login_required_api
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
        "scanner": current_app.scanner.get_scan_status(),
    }
    return jsonify(stats)


@api_bp.route("/ips")
@login_required_api
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

    if order_by == "smart_score":
        ips = query.all()
        result = [ip.to_dict() for ip in ips]
        max_speed = max((d["avg_download_speed"] or 0 for d in result), default=1)
        max_latency = max((d["avg_latency"] or 0 for d in result), default=1)
        for d in result:
            d["smart_score"] = round(
                compute_smart_score(d, max_speed, max_latency), 4
            )
        result.sort(key=lambda d: d["smart_score"], reverse=True)
        return jsonify({"ips": result, "total": len(result)})

    if order_by in VALID_SORT_COLUMNS:
        col = getattr(IP, order_by)
        query = query.order_by(col.desc() if order_dir == "DESC" else col.asc())

    ips = query.all()
    result = [ip.to_dict() for ip in ips]
    return jsonify({"ips": result, "total": len(result)})


@api_bp.route("/ip")
@login_required_api
def get_ip_detail():
    ip_address = request.args.get("ip")
    if not ip_address:
        return jsonify({"error": "IP required"}), 400

    ip = IP.query.filter_by(ip_address=ip_address).first()
    if not ip:
        return jsonify({"error": "IP not found"}), 404

    return jsonify(ip.to_dict())


@api_bp.route("/history")
@login_required_api
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
@login_required_api
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
@login_required_api
def monitor_status():
    return jsonify(current_app.monitor.get_status())


@api_bp.route("/scan/initial", methods=["POST"])
@login_required_api
def start_initial_scan():
    scanner = current_app.scanner
    if scanner._is_scanning:
        logger.info("Initial scan request rejected: scan already running")
        return jsonify({"status": "rejected", "reason": "scan already running"}), 409

    data = request.get_json(silent=True) or {}
    app = current_app._get_current_object()

    logger.info(
        f"Initial scan requested via API with params: "
        f"min_speed={data.get('min_speed', 10.0)}, "
        f"max_loss={data.get('max_loss', 0.25)}, "
        f"max_latency={data.get('max_latency', 1000)}, "
        f"test_count={data.get('test_count', 50)}"
    )

    def run_scan():
        try:
            results, metadata = app.scanner.initial_scan(
                min_speed=data.get("min_speed", 10.0),
                max_loss=data.get("max_loss", 0.25),
                max_latency=data.get("max_latency", 1000),
                test_count=data.get("test_count", 50),
            )
            logger.info(f"Initial scan thread finished: {metadata.get('status', 'unknown')}")
        except Exception as e:
            logger.error(f"Initial scan thread crashed: {e}", exc_info=True)

    threading.Thread(target=run_scan, daemon=True, name="initial-scan").start()
    return jsonify({"status": "started", "message": "Initial scan started in background"})


@api_bp.route("/scan/stop", methods=["POST"])
@login_required_api
def stop_scan():
    cancelled = current_app.scanner.cancel_scan()
    if cancelled:
        return jsonify({"status": "cancelling"})
    return jsonify({"status": "no_scan_running"})


@api_bp.route("/scan/status")
@login_required_api
def scan_status():
    return jsonify(current_app.scanner.get_scan_status())


@api_bp.route("/scan/schedule/start", methods=["POST"])
@login_required_api
def start_scan_schedule():
    data = request.get_json(silent=True) or {}
    interval = data.get("interval", 3600)
    current_app.scanner.start_schedule(interval=interval)
    return jsonify({
        "status": "started",
        "interval": current_app.scanner._schedule_interval,
    })


@api_bp.route("/scan/schedule/stop", methods=["POST"])
@login_required_api
def stop_scan_schedule():
    current_app.scanner.stop_schedule()
    return jsonify({"status": "stopped"})


@api_bp.route("/scan/schedule/interval", methods=["POST"])
@login_required_api
def set_scan_schedule_interval():
    data = request.get_json(silent=True) or {}
    interval = data.get("interval", 3600)
    current_app.scanner.set_schedule_interval(interval)
    return jsonify({
        "status": "updated",
        "interval": current_app.scanner._schedule_interval,
    })


@api_bp.route("/scan/test", methods=["POST"])
@login_required_api
def test_now():
    app = current_app._get_current_object()

    def run_test():
        results = app.monitor.trigger_immediate_test()
        logger.info(f"Immediate test completed: {len(results)} results")

    threading.Thread(target=run_test, daemon=True).start()
    return jsonify({"status": "started", "message": "Test started"})


@api_bp.route("/monitor/start", methods=["POST"])
@login_required_api
def start_monitor():
    data = request.get_json(silent=True) or {}
    interval = data.get("interval", 120)
    current_app.monitor.set_interval(interval)
    current_app.monitor.start(run_immediately=True)
    return jsonify({"status": "started", "interval": interval})


@api_bp.route("/monitor/stop", methods=["POST"])
@login_required_api
def stop_monitor():
    current_app.monitor.stop()
    return jsonify({"status": "stopped"})


@api_bp.route("/monitor/interval", methods=["POST"])
@login_required_api
def set_interval():
    data = request.get_json(silent=True) or {}
    interval = data.get("interval", 120)
    current_app.monitor.set_interval(interval)
    return jsonify({"status": "updated", "interval": interval})


@api_bp.route("/ip/deactivate", methods=["POST"])
@login_required_api
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


@api_bp.route("/ips/deactivate-all", methods=["POST"])
@login_required_api
def deactivate_all_ips():
    count = IP.query.filter_by(is_active=True).update({"is_active": False})
    db.session.commit()
    return jsonify({"status": "deactivated", "count": count})


@api_bp.route("/ips/deactivate-dead", methods=["POST"])
@login_required_api
def deactivate_dead_ips():
    """Deactivate active IPs whose download speed has been 0 over a range.

    Accepts JSON body:
        mode: "tests" | "hours"
        value: int  (last N tests  or  last N hours)

    Logic: for each active IP, look at the relevant test window.
    If *every* test in that window has download_speed_mbps <= 0 (or NULL),
    the IP is considered dead and gets deactivated.
    IPs with zero tests in the window are NOT touched.
    """
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "tests")
    value = int(data.get("value", 10))

    if mode == "hours":
        cutoff = datetime.now(timezone.utc) - timedelta(hours=value)
        dead_ids = (
            db.session.query(TestResult.ip_id)
            .join(IP)
            .filter(IP.is_active == True, TestResult.test_time >= cutoff)  # noqa: E712
            .group_by(TestResult.ip_id)
            .having(
                func.sum(
                    db.case((TestResult.download_speed_mbps > 0, 1), else_=0)
                ) == 0
            )
            .all()
        )
    else:
        # "tests" mode — use window function via raw SQL
        from sqlalchemy import text

        dead_ids = db.session.execute(
            text("""
                SELECT ip_id FROM (
                    SELECT ip_id, download_speed_mbps,
                        ROW_NUMBER() OVER (
                            PARTITION BY ip_id ORDER BY test_time DESC
                        ) AS rn
                    FROM test_results
                    WHERE ip_id IN (SELECT id FROM ips WHERE is_active = 1)
                )
                WHERE rn <= :last_n
                GROUP BY ip_id
                HAVING SUM(CASE WHEN download_speed_mbps > 0 THEN 1 ELSE 0 END) = 0
            """),
            {"last_n": value},
        ).fetchall()

    ids = [row[0] for row in dead_ids]
    count = 0
    if ids:
        count = IP.query.filter(IP.id.in_(ids)).update(
            {"is_active": False}, synchronize_session=False
        )
        db.session.commit()

    return jsonify({"status": "deactivated", "count": count, "mode": mode, "value": value})


@api_bp.route("/ips/preview-dead")
@login_required_api
def preview_dead_ips():
    """Return the count of IPs that *would* be deactivated (dry-run)."""
    mode = request.args.get("mode", "tests")
    value = int(request.args.get("value", 10))

    if mode == "hours":
        cutoff = datetime.now(timezone.utc) - timedelta(hours=value)
        dead_ids = (
            db.session.query(TestResult.ip_id)
            .join(IP)
            .filter(IP.is_active == True, TestResult.test_time >= cutoff)  # noqa: E712
            .group_by(TestResult.ip_id)
            .having(
                func.sum(
                    db.case((TestResult.download_speed_mbps > 0, 1), else_=0)
                ) == 0
            )
            .all()
        )
    else:
        from sqlalchemy import text

        dead_ids = db.session.execute(
            text("""
                SELECT ip_id FROM (
                    SELECT ip_id, download_speed_mbps,
                        ROW_NUMBER() OVER (
                            PARTITION BY ip_id ORDER BY test_time DESC
                        ) AS rn
                    FROM test_results
                    WHERE ip_id IN (SELECT id FROM ips WHERE is_active = 1)
                )
                WHERE rn <= :last_n
                GROUP BY ip_id
                HAVING SUM(CASE WHEN download_speed_mbps > 0 THEN 1 ELSE 0 END) = 0
            """),
            {"last_n": value},
        ).fetchall()

    return jsonify({"count": len(dead_ids), "mode": mode, "value": value})
