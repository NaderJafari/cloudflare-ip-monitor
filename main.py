#!/usr/bin/env python3
"""
Cloudflare IP Monitor - Main Entry Point

Usage:
    python main.py scan          # Run initial scan to discover IPs
    python main.py monitor       # Start periodic monitoring
    python main.py dashboard     # Start web dashboard
    python main.py all           # Run everything (recommended)
    python main.py status        # Show current status
    python main.py export        # Export IPs to file
"""

import argparse
import csv
import json
import logging
import signal
import sys
import time

from app import create_app
from app.config import Config
from app.services.ip_service import get_active_ips


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format=Config.LOG_FORMAT)


def cmd_scan(args):
    app = create_app()
    print("\n" + "=" * 60)
    print("  Cloudflare IP Scanner - Initial Scan")
    print("=" * 60)
    print(f"\nConfiguration:")
    print(f"  - Min Speed: {args.min_speed} MB/s")
    print(f"  - Max Latency: {args.max_latency} ms")
    print(f"  - Max Loss Rate: {args.max_loss}")
    print(f"  - IPs to Test: {args.test_count}")
    print(f"\nStarting scan... This may take several minutes.\n")

    try:
        results, metadata = app.scanner.initial_scan(
            min_speed=args.min_speed,
            max_loss=args.max_loss,
            max_latency=args.max_latency,
            test_count=args.test_count,
            threads=args.threads,
        )

        print("\n" + "=" * 60)
        print("  Scan Complete!")
        print("=" * 60)
        print(f"\n  Total IPs Tested: {metadata.get('total_tested', 0)}")
        print(f"  IPs Passed Criteria: {metadata.get('passed', 0)}")
        print(f"  Duration: {metadata.get('duration_seconds', 0):.1f} seconds")

        if results:
            print("\n  Top 10 IPs by Speed:")
            print("  " + "-" * 56)
            print(
                f"  {'IP Address':<20} {'Speed (MB/s)':<12} {'Latency (ms)':<12} {'Loss'}"
            )
            print("  " + "-" * 56)
            for r in sorted(results, key=lambda x: x.download_speed, reverse=True)[
                :10
            ]:
                print(
                    f"  {r.ip_address:<20} {r.download_speed:<12.2f} "
                    f"{r.latency_ms:<12.0f} {r.loss_rate:.2%}"
                )

        print("\n")
        return 0

    except Exception as e:
        logging.error(f"Scan failed: {e}")
        return 1


def cmd_monitor(args):
    app = create_app()
    print("\n" + "=" * 60)
    print("  Cloudflare IP Monitor - Periodic Monitoring")
    print("=" * 60)
    print(f"\n  Interval: {args.interval} seconds")
    print(f"  Press Ctrl+C to stop\n")

    monitor = app.monitor
    monitor.set_interval(args.interval)

    if args.scan_first:
        logging.info("Running initial scan...")
        results, metadata = app.scanner.initial_scan()
        logging.info(f"Initial scan complete: {metadata}")

    monitor.start(run_immediately=True)

    def signal_handler(signum, frame):
        logging.info(f"Received signal {signum}, shutting down...")
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        while monitor.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop()

    return 0


def cmd_dashboard(args):
    app = create_app()
    print("\n" + "=" * 60)
    print("  Cloudflare IP Monitor - Web Dashboard")
    print("=" * 60)
    print(f"  Running at: http://localhost:{args.port}")
    print(f"\n  Admin Login:")
    print(f"    Username: {Config.ADMIN_USERNAME}")
    print(f"    Password: {Config.ADMIN_PASSWORD}")
    print("=" * 60 + "\n")

    if not args.no_monitor:
        app.monitor.start(run_immediately=False)

    try:
        app.run(host=args.host, port=args.port, threaded=True)
    except KeyboardInterrupt:
        print("\nShutting down...")
        app.monitor.stop()

    return 0


def cmd_all(args):
    app = create_app()
    print("\n" + "=" * 60)
    print("  Cloudflare IP Monitor - Full Setup")
    print("=" * 60)

    with app.app_context():
        active_ips = get_active_ips()

    if not active_ips or args.force_scan:
        print("\nNo active IPs found. Running initial scan first...")
        print(f"  - Min Speed: {args.min_speed} MB/s")
        print(f"  - Max Latency: {args.max_latency} ms")
        print(f"  - Max Loss Rate: {args.max_loss}")
        print(f"\nThis may take several minutes...\n")

        results, metadata = app.scanner.initial_scan(
            min_speed=args.min_speed,
            max_loss=args.max_loss,
            max_latency=args.max_latency,
            test_count=args.test_count,
        )
        print(f"\nInitial scan complete: {metadata.get('passed', 0)} IPs found")
    else:
        print(f"\nFound {len(active_ips)} active IPs in database")

    print(f"\nStarting dashboard and monitoring...")
    print(f"  - Dashboard: http://localhost:{args.port}")
    print(f"  - Monitor Interval: {args.interval} seconds")
    print(f"\n  Admin Login:")
    print(f"    Username: {Config.ADMIN_USERNAME}")
    print(f"    Password: {Config.ADMIN_PASSWORD}")

    app.monitor.set_interval(args.interval)
    app.monitor.start(run_immediately=True)

    try:
        app.run(host=args.host, port=args.port, threaded=True)
    except KeyboardInterrupt:
        print("\nShutting down...")
        app.monitor.stop()

    return 0


def cmd_status(args):
    app = create_app()
    with app.app_context():
        from sqlalchemy import func

        from app.extensions import db
        from app.models import IP, TestResult

        total_active = IP.query.filter_by(is_active=True).count()
        total_tests = TestResult.query.count()

        row = (
            db.session.query(
                func.avg(IP.avg_download_speed),
                func.max(IP.best_download_speed),
                func.avg(IP.avg_latency),
                func.min(IP.best_latency),
            )
            .filter(IP.is_active == True)  # noqa: E712
            .first()
        )

        print("\n" + "=" * 60)
        print("  Cloudflare IP Monitor - Status")
        print("=" * 60)
        print(f"\n  Database Status:")
        print(f"    - Active IPs: {total_active}")
        print(f"    - Total Tests: {total_tests}")
        print(f"\n  Performance Averages:")
        print(f"    - Avg Speed: {(row[0] or 0):.2f} MB/s")
        print(f"    - Best Speed: {(row[1] or 0):.2f} MB/s")
        print(f"    - Avg Latency: {(row[2] or 0):.0f} ms")
        print(f"    - Best Latency: {(row[3] or 0):.0f} ms")

        monitor_status = app.monitor.get_status()
        print(f"\n  Monitor Status:")
        print(f"    - Running: {monitor_status.get('is_running', False)}")
        print(f"    - Interval: {monitor_status.get('interval_seconds', 0)}s")
        print(f"    - Test Count: {monitor_status.get('test_count', 0)}")

        top_ips = (
            IP.query.filter_by(is_active=True)
            .order_by(IP.avg_download_speed.desc())
            .limit(5)
            .all()
        )
        if top_ips:
            print(f"\n  Top IPs by Speed:")
            for ip in top_ips:
                print(
                    f"    - {ip.ip_address}: {(ip.avg_download_speed or 0):.2f} MB/s"
                )

        print("\n")
    return 0


def cmd_export(args):
    app = create_app()
    with app.app_context():
        from app.models import IP

        ips = (
            IP.query.filter_by(is_active=True)
            .order_by(IP.avg_download_speed.desc())
            .all()
        )

        if args.format == "txt":
            with open(args.output, "w") as f:
                for ip in ips:
                    f.write(f"{ip.ip_address}\n")
        elif args.format == "csv":
            with open(args.output, "w", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "ip_address",
                        "avg_download_speed",
                        "avg_latency",
                        "avg_loss_rate",
                        "total_tests",
                    ],
                )
                writer.writeheader()
                for ip in ips:
                    writer.writerow(
                        {
                            "ip_address": ip.ip_address,
                            "avg_download_speed": ip.avg_download_speed or 0,
                            "avg_latency": ip.avg_latency or 0,
                            "avg_loss_rate": ip.avg_loss_rate or 0,
                            "total_tests": ip.total_tests or 0,
                        }
                    )
        elif args.format == "json":
            with open(args.output, "w") as f:
                json.dump([ip.to_dict() for ip in ips], f, indent=2, default=str)

        print(f"Exported {len(ips)} IPs to {args.output}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Cloudflare IP Monitor - Discover and monitor optimal Cloudflare IPs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py all                    # Run everything (recommended for first time)
  python main.py scan -s 15             # Scan for IPs with min 15 MB/s speed
  python main.py dashboard              # Start web dashboard only
  python main.py monitor -i 300         # Monitor every 5 minutes
  python main.py status                 # Show current status
  python main.py export -o ips.txt      # Export IPs to file
        """,
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run initial scan to discover IPs")
    scan_parser.add_argument(
        "-s", "--min-speed", type=float, default=10.0, help="Min speed in MB/s"
    )
    scan_parser.add_argument(
        "-l", "--max-latency", type=int, default=1000, help="Max latency in ms"
    )
    scan_parser.add_argument(
        "-r", "--max-loss", type=float, default=0.25, help="Max loss rate"
    )
    scan_parser.add_argument(
        "-n", "--test-count", type=int, default=50, help="Number of IPs to test"
    )
    scan_parser.add_argument(
        "-t", "--threads", type=int, default=300, help="Concurrent threads"
    )
    scan_parser.set_defaults(func=cmd_scan)

    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Start periodic monitoring")
    monitor_parser.add_argument(
        "-i", "--interval", type=int, default=120, help="Test interval in seconds"
    )
    monitor_parser.add_argument(
        "--scan-first", action="store_true", help="Run initial scan before monitoring"
    )
    monitor_parser.set_defaults(func=cmd_monitor)

    # Dashboard command
    dash_parser = subparsers.add_parser("dashboard", help="Start web dashboard")
    dash_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    dash_parser.add_argument(
        "--port", type=int, default=8080, help="Port to listen on"
    )
    dash_parser.add_argument(
        "--no-monitor", action="store_true", help="Do not auto-start monitor"
    )
    dash_parser.set_defaults(func=cmd_dashboard)

    # All command (recommended)
    all_parser = subparsers.add_parser(
        "all", help="Run initial scan (if needed) + dashboard + monitoring"
    )
    all_parser.add_argument(
        "-s", "--min-speed", type=float, default=10.0, help="Min speed in MB/s"
    )
    all_parser.add_argument(
        "-l", "--max-latency", type=int, default=1000, help="Max latency in ms"
    )
    all_parser.add_argument(
        "-r", "--max-loss", type=float, default=0.25, help="Max loss rate"
    )
    all_parser.add_argument(
        "-n", "--test-count", type=int, default=50, help="Number of IPs to test"
    )
    all_parser.add_argument(
        "-i", "--interval", type=int, default=120, help="Monitor interval in seconds"
    )
    all_parser.add_argument("--host", default="0.0.0.0", help="Dashboard host")
    all_parser.add_argument(
        "--port", type=int, default=8080, help="Dashboard port"
    )
    all_parser.add_argument(
        "--force-scan", action="store_true", help="Force initial scan even if IPs exist"
    )
    all_parser.set_defaults(func=cmd_all)

    # Status command
    status_parser = subparsers.add_parser("status", help="Show current status")
    status_parser.set_defaults(func=cmd_status)

    # Export command
    export_parser = subparsers.add_parser("export", help="Export IPs to file")
    export_parser.add_argument(
        "-o", "--output", default="ips.txt", help="Output file"
    )
    export_parser.add_argument(
        "-f", "--format", choices=["txt", "csv", "json"], default="txt",
        help="Output format",
    )
    export_parser.set_defaults(func=cmd_export)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    setup_logging(args.verbose)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
