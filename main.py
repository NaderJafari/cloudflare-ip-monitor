#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare IP Monitor - Main Entry Point
A complete solution for discovering and monitoring Cloudflare IPs

Usage:
    python main.py scan          # Run initial scan to discover IPs
    python main.py monitor       # Start periodic monitoring
    python main.py dashboard     # Start web dashboard
    python main.py all           # Run everything (recommended)
"""

import argparse
import logging
import sys
import signal
import time
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from config import INITIAL_SCAN_CONFIG, MONITOR_CONFIG, DASHBOARD_CONFIG
from database import db
from scanner import run_initial_scan, scanner
from monitor import start_monitoring, stop_monitoring, monitor, MonitorDaemon
from dashboard import run_dashboard


def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
        ]
    )


def cmd_scan(args):
    """Run initial scan to discover good IPs"""
    print("\n" + "="*60)
    print("  Cloudflare IP Scanner - Initial Scan")
    print("="*60)
    print(f"\nConfiguration:")
    print(f"  - Min Speed: {args.min_speed} MB/s")
    print(f"  - Max Latency: {args.max_latency} ms")
    print(f"  - Max Loss Rate: {args.max_loss}")
    print(f"  - IPs to Test: {args.test_count}")
    print(f"\nStarting scan... This may take several minutes.\n")
    
    try:
        results, metadata = run_initial_scan(
            min_speed=args.min_speed,
            max_loss=args.max_loss,
            max_latency=args.max_latency,
            test_count=args.test_count,
            threads=args.threads
        )
        
        print("\n" + "="*60)
        print("  Scan Complete!")
        print("="*60)
        print(f"\n  Total IPs Tested: {metadata.get('total_tested', 0)}")
        print(f"  IPs Passed Criteria: {metadata.get('passed', 0)}")
        print(f"  Duration: {metadata.get('duration_seconds', 0):.1f} seconds")
        
        if results:
            print("\n  Top 10 IPs by Speed:")
            print("  " + "-"*56)
            print(f"  {'IP Address':<20} {'Speed (MB/s)':<12} {'Latency (ms)':<12} {'Loss'}")
            print("  " + "-"*56)
            for r in sorted(results, key=lambda x: x.download_speed, reverse=True)[:10]:
                print(f"  {r.ip_address:<20} {r.download_speed:<12.2f} {r.latency_ms:<12.0f} {r.loss_rate:.2%}")
        
        print("\n")
        return 0
        
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        return 1


def cmd_monitor(args):
    """Start periodic monitoring"""
    print("\n" + "="*60)
    print("  Cloudflare IP Monitor - Periodic Monitoring")
    print("="*60)
    print(f"\n  Interval: {args.interval} seconds")
    print(f"  Press Ctrl+C to stop\n")
    
    daemon = MonitorDaemon(interval_seconds=args.interval)
    
    try:
        daemon.run(run_initial_scan_first=args.scan_first)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        daemon.stop()
    
    return 0


def cmd_dashboard(args):
    """Start the web dashboard"""
    print("\n" + "="*60)
    print("  Cloudflare IP Monitor - Web Dashboard")
    print("="*60)
    
    run_dashboard(
        host=args.host,
        port=args.port,
        auto_start_monitor=not args.no_monitor
    )
    return 0


def cmd_all(args):
    """Run initial scan (if no IPs) then start dashboard with monitoring"""
    print("\n" + "="*60)
    print("  Cloudflare IP Monitor - Full Setup")
    print("="*60)
    
    # Check if we have any IPs
    active_ips = db.get_active_ips()
    
    if not active_ips or args.force_scan:
        print("\nNo active IPs found. Running initial scan first...")
        print(f"  - Min Speed: {args.min_speed} MB/s")
        print(f"  - Max Latency: {args.max_latency} ms")
        print(f"  - Max Loss Rate: {args.max_loss}")
        print(f"\nThis may take several minutes...\n")
        
        results, metadata = run_initial_scan(
            min_speed=args.min_speed,
            max_loss=args.max_loss,
            max_latency=args.max_latency,
            test_count=args.test_count
        )
        
        print(f"\nInitial scan complete: {metadata.get('passed', 0)} IPs found")
    else:
        print(f"\nFound {len(active_ips)} active IPs in database")
    
    print(f"\nStarting dashboard and monitoring...")
    print(f"  - Dashboard: http://localhost:{args.port}")
    print(f"  - Monitor Interval: {args.interval} seconds")
    
    run_dashboard(
        host=args.host,
        port=args.port,
        auto_start_monitor=True
    )
    
    return 0


def cmd_status(args):
    """Show current status"""
    print("\n" + "="*60)
    print("  Cloudflare IP Monitor - Status")
    print("="*60)
    
    stats = db.get_statistics()
    monitor_status = monitor.get_status()
    
    print(f"\n  Database Status:")
    print(f"    - Active IPs: {stats.get('total_active_ips', 0)}")
    print(f"    - Total Tests: {stats.get('total_tests', 0)}")
    print(f"    - Tests Today: {stats.get('tests_today', 0)}")
    
    print(f"\n  Performance Averages:")
    print(f"    - Avg Speed: {stats.get('avg_speed', 0):.2f} MB/s")
    print(f"    - Best Speed: {stats.get('best_speed', 0):.2f} MB/s")
    print(f"    - Avg Latency: {stats.get('avg_latency', 0):.0f} ms")
    print(f"    - Best Latency: {stats.get('best_latency', 0):.0f} ms")
    
    print(f"\n  Monitor Status:")
    print(f"    - Running: {monitor_status.get('is_running', False)}")
    print(f"    - Interval: {monitor_status.get('interval_seconds', 0)}s")
    print(f"    - Test Count: {monitor_status.get('test_count', 0)}")
    
    if stats.get('top_ips'):
        print(f"\n  Top IPs by Speed:")
        for ip in stats['top_ips'][:5]:
            print(f"    - {ip['ip_address']}: {ip['avg_download_speed']:.2f} MB/s")
    
    print("\n")
    return 0


def cmd_export(args):
    """Export IPs to file"""
    ips = db.get_all_ips_with_stats(order_by='avg_download_speed', order_dir='DESC')
    
    if args.format == 'txt':
        with open(args.output, 'w') as f:
            for ip in ips:
                f.write(f"{ip['ip_address']}\n")
    elif args.format == 'csv':
        import csv
        with open(args.output, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['ip_address', 'avg_download_speed', 
                                                   'avg_latency', 'avg_loss_rate', 'total_tests'])
            writer.writeheader()
            for ip in ips:
                writer.writerow({
                    'ip_address': ip['ip_address'],
                    'avg_download_speed': ip.get('avg_download_speed', 0),
                    'avg_latency': ip.get('avg_latency', 0),
                    'avg_loss_rate': ip.get('avg_loss_rate', 0),
                    'total_tests': ip.get('total_tests', 0)
                })
    elif args.format == 'json':
        import json
        with open(args.output, 'w') as f:
            json.dump(ips, f, indent=2, default=str)
    
    print(f"Exported {len(ips)} IPs to {args.output}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Cloudflare IP Monitor - Discover and monitor optimal Cloudflare IPs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py all                    # Run everything (recommended for first time)
  python main.py scan -s 15             # Scan for IPs with min 15 MB/s speed
  python main.py dashboard              # Start web dashboard only
  python main.py monitor -i 300         # Monitor every 5 minutes
  python main.py status                 # Show current status
  python main.py export -o ips.txt      # Export IPs to file
        """
    )
    
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run initial scan to discover IPs')
    scan_parser.add_argument('-s', '--min-speed', type=float, default=10.0, help='Min speed in MB/s (default: 10)')
    scan_parser.add_argument('-l', '--max-latency', type=int, default=1000, help='Max latency in ms (default: 1000)')
    scan_parser.add_argument('-r', '--max-loss', type=float, default=0.25, help='Max loss rate (default: 0.25)')
    scan_parser.add_argument('-n', '--test-count', type=int, default=50, help='Number of IPs to test (default: 50)')
    scan_parser.add_argument('-t', '--threads', type=int, default=300, help='Concurrent threads (default: 300)')
    scan_parser.set_defaults(func=cmd_scan)
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Start periodic monitoring')
    monitor_parser.add_argument('-i', '--interval', type=int, default=120, help='Test interval in seconds (default: 120)')
    monitor_parser.add_argument('--scan-first', action='store_true', help='Run initial scan before monitoring')
    monitor_parser.set_defaults(func=cmd_monitor)
    
    # Dashboard command
    dash_parser = subparsers.add_parser('dashboard', help='Start web dashboard')
    dash_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    dash_parser.add_argument('--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    dash_parser.add_argument('--no-monitor', action='store_true', help='Do not auto-start monitor')
    dash_parser.set_defaults(func=cmd_dashboard)
    
    # All command (recommended)
    all_parser = subparsers.add_parser('all', help='Run initial scan (if needed) + dashboard + monitoring')
    all_parser.add_argument('-s', '--min-speed', type=float, default=10.0, help='Min speed in MB/s (default: 10)')
    all_parser.add_argument('-l', '--max-latency', type=int, default=1000, help='Max latency in ms (default: 1000)')
    all_parser.add_argument('-r', '--max-loss', type=float, default=0.25, help='Max loss rate (default: 0.25)')
    all_parser.add_argument('-n', '--test-count', type=int, default=50, help='Number of IPs to test (default: 50)')
    all_parser.add_argument('-i', '--interval', type=int, default=120, help='Monitor interval in seconds (default: 120)')
    all_parser.add_argument('--host', default='0.0.0.0', help='Dashboard host (default: 0.0.0.0)')
    all_parser.add_argument('--port', type=int, default=8080, help='Dashboard port (default: 8080)')
    all_parser.add_argument('--force-scan', action='store_true', help='Force initial scan even if IPs exist')
    all_parser.set_defaults(func=cmd_all)
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show current status')
    status_parser.set_defaults(func=cmd_status)
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export IPs to file')
    export_parser.add_argument('-o', '--output', default='ips.txt', help='Output file (default: ips.txt)')
    export_parser.add_argument('-f', '--format', choices=['txt', 'csv', 'json'], default='txt', help='Output format')
    export_parser.set_defaults(func=cmd_export)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    setup_logging(args.verbose)
    
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
