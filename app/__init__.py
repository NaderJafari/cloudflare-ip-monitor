import logging

from flask import Flask
from sqlalchemy import event

from app.config import Config
from app.extensions import db


def create_app(config=None):
    app = Flask(__name__)
    app.config.from_object(Config)

    if config:
        app.config.update(config)

    Config.DATA_DIR.mkdir(exist_ok=True)
    Config.LOGS_DIR.mkdir(exist_ok=True)

    db.init_app(app)

    with app.app_context():
        # Set SQLite pragmas for performance
        @event.listens_for(db.engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

        db.create_all()

    from app.api import api_bp
    from app.dashboard import dashboard_bp

    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(dashboard_bp)

    # Attach services to app for shared access
    from app.services.scanner import CloudflareScanner
    from app.services.monitor import PeriodicMonitor

    app.scanner = CloudflareScanner(app)
    app.monitor = PeriodicMonitor(app)

    # Auto-start scan scheduler if configured
    if app.scanner._schedule_interval > 0:
        app.scanner.start_schedule()

    if not app.debug or app.testing:
        logging.basicConfig(
            level=getattr(logging, Config.LOG_LEVEL),
            format=Config.LOG_FORMAT,
        )

    return app
