from functools import wraps

from flask import redirect, render_template, request, session, url_for

from app.config import Config
from app.dashboard import dashboard_bp


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("dashboard.login"))
        return f(*args, **kwargs)
    return decorated


@dashboard_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == Config.ADMIN_USERNAME and password == Config.ADMIN_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("dashboard.index"))
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@dashboard_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("dashboard.login"))


@dashboard_bp.route("/")
@login_required
def index():
    return render_template("dashboard.html")
