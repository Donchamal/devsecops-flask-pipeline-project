import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, session, url_for
import requests
from requests.auth import HTTPBasicAuth
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = Path(os.environ.get("INSTANCE_DIR", BASE_DIR / "instance"))
DATABASE = INSTANCE_DIR / "users.db"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "local-development-key-change-before-deployment"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=1800,
)
CSRFProtect(app)


def get_db():
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db() as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        # Create the initial administrator once. Existing passwords are never overwritten.
        username = os.environ.get("ADMIN_USERNAME")
        password = os.environ.get("ADMIN_PASSWORD")
        if username and password:
            existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing is None:
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )


initialize_database()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access the dashboard.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


@app.get("/")
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.post("/login")
def authenticate():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with get_db() as db:
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        flash("Invalid username or password.", "danger")
        return redirect(url_for("login")), 303

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session.permanent = True
    flash("Welcome back! You are now signed in.", "success")
    return redirect(url_for("dashboard"))



def fetch_jenkins_data():
    """Fetch a small, read-only summary from Jenkins without exposing credentials."""
    base_url = os.environ.get("JENKINS_URL", "http://localhost:8080").rstrip("/")
    username = os.environ.get("JENKINS_USER")
    token = os.environ.get("JENKINS_TOKEN")
    job_name = os.environ.get("JENKINS_JOB", "DevSecOps-Flask-Pipeline")

    if not username or not token:
        return {"configured": False, "available": False,
                "message": "Jenkins credentials are not configured for this Flask process."}

    # Jenkins job URLs use /job/<job-name>/; quote the name to safely handle spaces.
    from urllib.parse import quote
    job_path = "/job/" + quote(job_name, safe="")
    api_url = base_url + job_path + "/api/json"
    params = {"tree": "name,lastBuild[number,result,building,duration,timestamp],"
                       "lastSuccessfulBuild[number,timestamp],"
                       "builds[number,result,building,duration,timestamp]{0,5}"}
    try:
        response = requests.get(
            api_url,
            params=params,
            auth=HTTPBasicAuth(username, token),
            timeout=5,
        )
        if response.status_code == 401 or response.status_code == 403:
            return {"configured": True, "available": False,
                    "message": "Jenkins rejected the API credentials or the account lacks read permission."}
        response.raise_for_status()
        payload = response.json()

        last_build = payload.get("lastBuild")
        if last_build:
            status = "BUILDING" if last_build.get("building") else (last_build.get("result") or "UNKNOWN")
            duration_ms = last_build.get("duration", 0)
            duration = f"{duration_ms / 1000:.1f} seconds" if duration_ms else "—"
        else:
            status, duration = "NO BUILDS", "—"

        history = []
        for build in payload.get("builds", []):
            history.append({
                "number": build.get("number"),
                "status": "BUILDING" if build.get("building") else (build.get("result") or "UNKNOWN"),
                "duration": f"{build.get('duration', 0) / 1000:.1f}s" if build.get("duration") else "—",
            })

        return {
            "configured": True,
            "available": True,
            "job_name": payload.get("name", job_name),
            "status": status,
            "last_build_number": last_build.get("number") if last_build else None,
            "duration": duration,
            "last_success_number": (payload.get("lastSuccessfulBuild") or {}).get("number"),
            "history": history,
            "message": "Live data retrieved from Jenkins.",
        }
    except requests.exceptions.Timeout:
        message = "Jenkins did not respond within 5 seconds. Check that it is running."
    except requests.exceptions.ConnectionError:
        message = "Cannot reach Jenkins. Check JENKINS_URL and that Jenkins is running."
    except requests.exceptions.HTTPError as exc:
        message = f"Jenkins returned HTTP {exc.response.status_code}. Check the job name and permissions."
    except (ValueError, requests.exceptions.RequestException):
        message = "Could not read Jenkins API data. Check the Jenkins URL and API response."
    return {"configured": True, "available": False, "message": message}


def fetch_sonarqube_data():
    """Fetch live SonarQube quality and security metrics."""

    base_url = os.environ.get("SONAR_URL", "http://localhost:9000").rstrip("/")
    token = os.environ.get("SONAR_TOKEN")
    project_key = os.environ.get("SONAR_PROJECT_KEY", "DevSecOps-Flask")

    if not token:
        return {
            "configured": False,
            "available": False,
            "message": "SonarQube token is not configured."
        }

    try:
        auth = HTTPBasicAuth(token, "")

        quality_response = requests.get(
            f"{base_url}/api/qualitygates/project_status",
            params={"projectKey": project_key},
            auth=auth,
            timeout=10
        )
        quality_response.raise_for_status()

        measures_response = requests.get(
            f"{base_url}/api/measures/component",
            params={
                "component": project_key,
                "metricKeys": (
                    "bugs,vulnerabilities,code_smells,coverage,"
                    "duplicated_lines_density,reliability_rating,"
                    "security_rating,sqale_rating,"
                    "security_hotspots,security_hotspots_reviewed"
                )
            },
            auth=auth,
            timeout=10
        )
        measures_response.raise_for_status()

        quality_data = quality_response.json().get("projectStatus", {})
        measures = measures_response.json().get(
            "component", {}
        ).get("measures", [])

        metrics = {
            item["metric"]: item.get("value", "0")
            for item in measures
        }

        return {
            "configured": True,
            "available": True,
            "quality_gate": quality_data.get("status", "UNKNOWN"),
            "conditions": quality_data.get("conditions", []),
            "bugs": metrics.get("bugs", "0"),
            "vulnerabilities": metrics.get("vulnerabilities", "0"),
            "code_smells": metrics.get("code_smells", "0"),
            "coverage": metrics.get("coverage", "0"),
            "duplications": metrics.get("duplicated_lines_density", "0"),
            "reliability_rating": metrics.get("reliability_rating", "0"),
            "security_rating": metrics.get("security_rating", "0"),
            "maintainability_rating": metrics.get("sqale_rating", "0"),
            "security_hotspots": metrics.get("security_hotspots", "0"),
            "hotspots_reviewed": metrics.get("security_hotspots_reviewed", "0"),
            "message": "Live SonarQube data retrieved successfully."
        }

    except requests.exceptions.Timeout:
        message = "SonarQube API request timed out."
    except requests.exceptions.ConnectionError:
        message = "Cannot connect to SonarQube. Check that it is running."
    except requests.exceptions.HTTPError as exc:
        message = f"SonarQube returned HTTP {exc.response.status_code}."
    except (ValueError, KeyError, requests.exceptions.RequestException):
        message = "Could not retrieve SonarQube project information."

    return {
        "configured": True,
        "available": False,
        "message": message
    }



@app.get("/api/jenkins")
@login_required
def jenkins_api_status():
    """Authenticated diagnostic endpoint; never returns the API token."""
    data = fetch_jenkins_data()
    status_code = 200 if data.get("available") else 503
    return data, status_code



@app.get("/dashboard")
@login_required
def dashboard():
    jenkins = fetch_jenkins_data()
    sonarqube = fetch_sonarqube_data()

    return render_template(
        "dashboard.html",
        username=session.get("username", "User"),
        jenkins=jenkins,
        sonarqube=sonarqube,
    )




@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (session["user_id"],)
            ).fetchone()

            if not user or not check_password_hash(
                user["password_hash"], current_password
            ):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for("change_password"))

            if len(new_password) < 12:
                flash("New password must be at least 12 characters.", "danger")
                return redirect(url_for("change_password"))

            if new_password != confirm_password:
                flash("New passwords do not match.", "danger")
                return redirect(url_for("change_password"))

            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_password), session["user_id"])
            )

        flash("Password changed successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


@app.get("/health")
def health():
    return {"status": "healthy"}, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
