
import pytest
import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash
import app as flask_app
from app import app
from unittest.mock import patch, Mock
import requests

@pytest.fixture
def client(tmp_path, monkeypatch):
    test_db = tmp_path / "test_users.db"

    monkeypatch.setattr(flask_app, "DATABASE", test_db)
    monkeypatch.setattr(flask_app, "INSTANCE_DIR", tmp_path)

    with sqlite3.connect(test_db) as db:
        db.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("testuser", generate_password_hash("TestPassword123!"))
        )

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with app.test_client() as client:
        yield client


def test_home_page(client):
    response = client.get("/")
    assert response.status_code == 200


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code in (302, 401)


def test_logout(client):
    response = client.post("/logout")
    assert response.status_code in (200, 302)


def test_jenkins_api_requires_login(client):
    response = client.get("/api/jenkins")
    assert response.status_code in (302, 401)


def test_successful_login(client):
    response = client.post(
        "/login",
        data={"username": "testuser", "password": "TestPassword123!"},
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_login_wrong_password(client):
    response = client.post(
        "/login",
        data={"username": "testuser", "password": "WrongPassword123!"},
    )
    assert response.status_code == 303
    assert response.headers["Location"].endswith("/")


def test_login_unknown_user(client):
    response = client.post(
        "/login",
        data={"username": "unknown", "password": "TestPassword123!"},
    )
    assert response.status_code == 303


def test_logged_in_user_redirect(client):
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "testuser"

    response = client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_jenkins_missing_credentials(monkeypatch):
    monkeypatch.delenv("JENKINS_USER", raising=False)
    monkeypatch.delenv("JENKINS_TOKEN", raising=False)

    result = flask_app.fetch_jenkins_data()

    assert result["configured"] is False
    assert result["available"] is False


@patch("app.requests.get")
def test_jenkins_success(mock_get, monkeypatch):
    monkeypatch.setenv("JENKINS_USER", "testuser")
    monkeypatch.setenv("JENKINS_TOKEN", "test-token")

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "name": "DevSecOps-Flask-Pipeline",
        "lastBuild": {
            "number": 27,
            "result": "SUCCESS",
            "building": False,
            "duration": 120000
        },
        "lastSuccessfulBuild": {"number": 27},
        "builds": [
            {
                "number": 27,
                "result": "SUCCESS",
                "building": False,
                "duration": 120000
            }
        ]
    }
    mock_get.return_value = mock_response

    result = flask_app.fetch_jenkins_data()

    assert result["available"] is True
    assert result["status"] == "SUCCESS"
    assert result["last_build_number"] == 27
    assert len(result["history"]) == 1

@pytest.mark.parametrize("status_code", [401, 403])
@patch("app.requests.get")
def test_jenkins_authentication_failure(
    mock_get, monkeypatch, status_code
):
    monkeypatch.setenv("JENKINS_USER", "testuser")
    monkeypatch.setenv("JENKINS_TOKEN", "test-token")

    mock_response = Mock()
    mock_response.status_code = status_code
    mock_get.return_value = mock_response

    result = flask_app.fetch_jenkins_data()

    assert result["configured"] is True
    assert result["available"] is False
    assert "rejected" in result["message"]


@patch("app.requests.get")
def test_jenkins_timeout(mock_get, monkeypatch):
    monkeypatch.setenv("JENKINS_USER", "testuser")
    monkeypatch.setenv("JENKINS_TOKEN", "test-token")
    mock_get.side_effect = requests.exceptions.Timeout

    result = flask_app.fetch_jenkins_data()

    assert result["available"] is False
    assert "5 seconds" in result["message"]

def test_sonarqube_missing_token(monkeypatch):
    monkeypatch.delenv("SONAR_TOKEN", raising=False)

    result = flask_app.fetch_sonarqube_data()

    assert result["configured"] is False
    assert result["available"] is False
    assert "not configured" in result["message"]

@patch("app.requests.get")
def test_sonarqube_success(mock_get, monkeypatch):
    monkeypatch.setenv("SONAR_TOKEN", "test-sonar-token")
    monkeypatch.setenv("SONAR_URL", "http://localhost:9000")
    monkeypatch.setenv("SONAR_PROJECT_KEY", "DevSecOps-Flask")

    quality_response = Mock()
    quality_response.json.return_value = {
        "projectStatus": {
            "status": "OK",
            "conditions": []
        }
    }

    measures_response = Mock()
    measures_response.json.return_value = {
        "component": {
            "measures": [
                {"metric": "bugs", "value": "0"},
                {"metric": "vulnerabilities", "value": "0"},
                {"metric": "code_smells", "value": "1"},
                {"metric": "coverage", "value": "85.0"},
                {"metric": "duplicated_lines_density", "value": "0.0"},
                {"metric": "reliability_rating", "value": "1"},
                {"metric": "security_rating", "value": "1"},
                {"metric": "sqale_rating", "value": "1"},
                {"metric": "security_hotspots", "value": "2"},
                {"metric": "security_hotspots_reviewed", "value": "100.0"}
            ]
        }
    }

    mock_get.side_effect = [quality_response, measures_response]

    result = flask_app.fetch_sonarqube_data()

    assert result["available"] is True
    assert result["quality_gate"] == "OK"
    assert result["coverage"] == "85.0"
    assert result["bugs"] == "0"
    assert result["security_hotspots"] == "2"

def test_change_password_page(client):
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "testuser"

    response = client.get("/change-password")
    assert response.status_code == 200


def test_change_password_success(client):
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "testuser"

    response = client.post(
        "/change-password",
        data={
            "current_password": "TestPassword123!",
            "new_password": "NewPassword123!",
            "confirm_password": "NewPassword123!",
        },
    )

    assert response.status_code == 302

    with client.session_transaction() as session:
        assert session["user_id"] == 1


def test_change_password_wrong_current_password(client):
    with client.session_transaction() as session:
        session["user_id"] = 1

    response = client.post(
        "/change-password",
        data={
            "current_password": "WrongPassword123!",
            "new_password": "NewPassword123!",
            "confirm_password": "NewPassword123!",
        },
    )

    assert response.status_code == 302


def test_change_password_too_short(client):
    with client.session_transaction() as session:
        session["user_id"] = 1

    response = client.post(
        "/change-password",
        data={
            "current_password": "TestPassword123!",
            "new_password": "Short123!",
            "confirm_password": "Short123!",
        },
    )

    assert response.status_code == 302


def test_change_password_mismatch(client):
    with client.session_transaction() as session:
        session["user_id"] = 1

    response = client.post(
        "/change-password",
        data={
            "current_password": "TestPassword123!",
            "new_password": "NewPassword123!",
            "confirm_password": "DifferentPassword123!",
        },
    )

    assert response.status_code == 302
