import hashlib

_original_md5 = hashlib.md5


def compatible_md5(data=b"", **kwargs):
    kwargs.pop("usedforsecurity", None)
    return _original_md5(data)


hashlib.md5 = compatible_md5

import re
import os
import io
import sqlite3
import ipaddress
import base64
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, abort, redirect, url_for, flash

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"
DATABASE = BASE_DIR / "threat_history.db"

load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "change-this-development-secret"
)

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()

VT_BASE_URL = "https://www.virustotal.com/api/v3"

REQUEST_TIMEOUT = 20


# --------------------------------------------------
# DATABASE SETUP
# --------------------------------------------------

def get_db_connection():
    connection = sqlite3.connect(str(DATABASE))
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                malicious INTEGER DEFAULT 0,
                suspicious INTEGER DEFAULT 0,
                harmless INTEGER DEFAULT 0,
                undetected INTEGER DEFAULT 0,
                status TEXT NOT NULL,
                details TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )


initialize_database()


# --------------------------------------------------
# INDICATOR VALIDATION
# --------------------------------------------------

def validate_ip(indicator):
    try:
        ipaddress.ip_address(indicator)
        return True
    except ValueError:
        return False


def validate_url(indicator):
    try:
        parsed = urlparse(indicator)

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.hostname:
            return False

        if any(character.isspace() for character in indicator):
            return False

        # Reject malformed hostname/port syntax.
        parsed.port

        return True

    except (ValueError, TypeError):
        return False


def classify_severity(malicious, suspicious):
    if malicious > 0:
        return "HIGH"

    if suspicious > 0:
        return "MEDIUM"

    return "LOW"


# --------------------------------------------------
# VIRUSTOTAL API
# --------------------------------------------------

def check_virustotal(indicator, indicator_type):
    """
    Retrieve an existing VirusTotal report.

    This function does not submit a URL for a new scan.
    """

    if not VT_API_KEY:
        return {
            "success": False,
            "error": "VirusTotal API key is missing. Check your .env file."
        }

    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json",
    }

    if indicator_type == "ip":
        if not validate_ip(indicator):
            return {
                "success": False,
                "error": "Please enter a valid IPv4 or IPv6 address."
            }

        endpoint = (
            VT_BASE_URL
            + "/ip_addresses/"
            + indicator
        )

    elif indicator_type == "url":
        if not validate_url(indicator):
            return {
                "success": False,
                "error": "Enter a valid HTTP or HTTPS URL."
            }

        url_id = base64.urlsafe_b64encode(
            indicator.encode("utf-8")
        ).decode("ascii").rstrip("=")

        endpoint = VT_BASE_URL + "/urls/" + url_id

    else:
        return {
            "success": False,
            "error": "Unsupported indicator type."
        }

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 404:
            return {
                "success": False,
                "error": (
                    "VirusTotal has no existing report for this indicator. "
                    "Try another indicator."
                )
            }

        if response.status_code == 401:
            return {
                "success": False,
                "error": (
                    "VirusTotal rejected the API key. "
                    "Check your key in the .env file."
                )
            }

        if response.status_code == 403:
            return {
                "success": False,
                "error": (
                    "VirusTotal denied access. "
                    "Check your API permissions and usage limits."
                )
            }

        if response.status_code == 429:
            return {
                "success": False,
                "error": (
                    "VirusTotal rate limit reached. "
                    "Please wait and try again later."
                )
            }

        response.raise_for_status()

        payload = response.json()

        attributes = payload.get(
            "data", {}
        ).get("attributes", {})

        stats = attributes.get(
            "last_analysis_stats", {}
        )

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))

        severity = classify_severity(
            malicious,
            suspicious
        )

        return {
            "success": True,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "severity": severity,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "status": "Completed",
            "details": (
                "Existing VirusTotal reputation report retrieved."
            ),
        }

    except requests.Timeout:
        return {
            "success": False,
            "error": "VirusTotal request timed out. Please try again."
        }

    except requests.RequestException:
        return {
            "success": False,
            "error": (
                "Could not contact VirusTotal. "
                "Check your internet connection and try again."
            )
        }

    except (ValueError, TypeError):
        return {
            "success": False,
            "error": "VirusTotal returned an unexpected response."
        }


# --------------------------------------------------
# SAVE INVESTIGATION
# --------------------------------------------------

def save_investigation(result):
    with get_db_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO investigations (
                indicator,
                indicator_type,
                severity,
                malicious,
                suspicious,
                harmless,
                undetected,
                status,
                details,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.get("indicator", ""),
                result.get("indicator_type", ""),
                result.get("severity", "UNKNOWN"),
                result.get("malicious", 0),
                result.get("suspicious", 0),
                result.get("harmless", 0),
                result.get("undetected", 0),
                result.get("status", "Failed"),
                result.get("details", result.get("error", "")),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

        return cursor.lastrowid


# --------------------------------------------------
# DASHBOARD STATISTICS
# --------------------------------------------------

def get_dashboard_data():
    with get_db_connection() as connection:

        total_scans = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM investigations
            WHERE status = 'Completed'
            """
        ).fetchone()["count"]

        high_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM investigations
            WHERE status = 'Completed'
              AND severity = 'HIGH'
            """
        ).fetchone()["count"]

        medium_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM investigations
            WHERE status = 'Completed'
              AND severity = 'MEDIUM'
            """
        ).fetchone()["count"]

        low_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM investigations
            WHERE status = 'Completed'
              AND severity = 'LOW'
            """
        ).fetchone()["count"]

        history = connection.execute(
            """
            SELECT *
            FROM investigations
            ORDER BY id DESC
            LIMIT 20
            """
        ).fetchall()

    return {
        "total_scans": total_scans,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "history": history,
    }


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():
    dashboard_data = get_dashboard_data()

    return render_template(
        "dashboard.html",
        result=None,
        error=None,
        **dashboard_data
    )


# --------------------------------------------------
# INVESTIGATE IP OR URL
# --------------------------------------------------

@app.route("/investigate", methods=["POST"])
def investigate():
    indicator = request.form.get(
        "indicator", ""
    ).strip()

    indicator_type = request.form.get(
        "indicator_type", ""
    ).strip().lower()

    if not indicator:
        flash("Please enter an IP address or URL.", "error")
        return redirect(url_for("home"))

    if indicator_type == "ip":
        if not validate_ip(indicator):
            flash("Enter a valid IP address.", "error")
            return redirect(url_for("home"))

    elif indicator_type == "url":
        if not validate_url(indicator):
            flash(
                "Enter a valid HTTP or HTTPS URL.",
                "error"
            )
            return redirect(url_for("home"))

    else:
        flash("Choose a valid indicator type.", "error")
        return redirect(url_for("home"))

    result = check_virustotal(
        indicator,
        indicator_type
    )

    if result.get("success"):
        result["status"] = "Completed"
        save_investigation(result)

    else:
        # Record failed attempts for investigation history.
        failed_record = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "severity": "UNKNOWN",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "status": "Failed",
            "details": result.get(
                "error",
                "Investigation failed."
            ),
        }

        save_investigation(failed_record)

    dashboard_data = get_dashboard_data()

    return render_template(
        "dashboard.html",
        result=result if result.get("success") else None,
        error=result.get("error"),
        **dashboard_data
    )


# --------------------------------------------------
# PDF REPORT DOWNLOAD
# --------------------------------------------------

@app.route("/report/<int:report_id>")
def download_report(report_id):
    with get_db_connection() as connection:
        record = connection.execute(
            """
            SELECT *
            FROM investigations
            WHERE id = ?
            """,
            (report_id,),
        ).fetchone()

    if record is None:
        abort(404)

    buffer = io.BytesIO()

    pdf = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=45,
        leftMargin=45,
        topMargin=45,
        bottomMargin=45,
    )

    styles = getSampleStyleSheet()

    story = []

    story.append(
        Paragraph(
            "Threat Intelligence Investigation Report",
            styles["Title"]
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Generated: "
            + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 20))

    report_rows = [
        ["Field", "Value"],
        ["Investigation ID", str(record["id"])],
        ["Indicator", str(record["indicator"])],
        ["Indicator Type", str(record["indicator_type"])],
        ["Severity", str(record["severity"])],
        ["Status", str(record["status"])],
        ["Malicious detections", str(record["malicious"])],
        ["Suspicious detections", str(record["suspicious"])],
        ["Harmless detections", str(record["harmless"])],
        ["Undetected", str(record["undetected"])],
        ["Investigation Date", str(record["created_at"])],
        ["Details", str(record["details"] or "No additional details")],
    ]

    table = Table(
        report_rows,
        colWidths=[150, 330],
        repeatRows=1,
    )

    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#12304A")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
        ])
    )

    story.append(table)

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Disclaimer: This report reflects the information "
            "available from the investigation at the time it was "
            "performed. A low severity result does not guarantee "
            "that an indicator is safe.",
            styles["BodyText"]
        )
    )

    pdf.build(story)

    buffer.seek(0)

    safe_indicator = re.sub(
        r"[^A-Za-z0-9_-]",
        "_",
        record["indicator"]
    )[:40]

    filename = (
        "threat_report_"
        + str(record["id"])
        + "_"
        + safe_indicator
        + ".pdf"
    )

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


# --------------------------------------------------
# APPLICATION ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    print("ENV file exists:", ENV_FILE.exists())
    print("VirusTotal API key loaded:", bool(VT_API_KEY))
    print("Database:", DATABASE)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )