import sqlite3
import json
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "investigations.db"


def get_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            sender TEXT,
            receiver TEXT,
            subject TEXT,
            prediction TEXT,
            confidence REAL,
            risk_score INTEGER,
            threat_level TEXT,
            risk_reasons TEXT,
            forensic_data TEXT,
            ioc_data TEXT,
            attachment_data TEXT,
            timeline_data TEXT
        )
    """)

    connection.commit()
    connection.close()
    return True


def generate_case_id():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM investigations")
    count = cursor.fetchone()[0]
    connection.close()
    return f"CASE-{count + 1:04d}"


def save_investigation(result, sender="", receiver="", subject=""):
    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    case_id = generate_case_id()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    prediction = result.get("prediction", "UNKNOWN")
    confidence = result.get("confidence", 0)
    risk_score = result.get("risk_score", 0)
    threat_level = result.get(
        "threat_level",
        result.get("threat", "UNKNOWN")
    )

    cursor.execute("""
        INSERT INTO investigations (
            case_id, timestamp, sender, receiver, subject,
            prediction, confidence, risk_score, threat_level,
            risk_reasons, forensic_data, ioc_data,
            attachment_data, timeline_data
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_id,
        timestamp,
        sender,
        receiver,
        subject,
        prediction,
        confidence,
        risk_score,
        threat_level,
        json.dumps(result.get("risk_reasons", []), default=str),
        json.dumps(result.get("forensics", {}), default=str),
        json.dumps(result.get("iocs", {}), default=str),
        json.dumps(result.get("attachments", {}), default=str),
        json.dumps(result.get("timeline", []), default=str)
    ))

    connection.commit()
    connection.close()
    return case_id


def get_all_investigations():
    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, case_id, timestamp, sender, receiver, subject,
               prediction, confidence, risk_score, threat_level
        FROM investigations
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    connection.close()
    return [dict(row) for row in rows]


def get_investigation(case_id):
    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM investigations WHERE case_id = ?",
        (case_id,)
    )

    row = cursor.fetchone()
    connection.close()

    if row is None:
        return None

    result = dict(row)

    for field in [
        "risk_reasons",
        "forensic_data",
        "ioc_data",
        "attachment_data",
        "timeline_data"
    ]:
        try:
            result[field] = json.loads(result[field])
        except Exception:
            result[field] = (
                [] if field in ("risk_reasons", "timeline_data")
                else {}
            )

    return result


def delete_investigation(case_id):
    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM investigations WHERE case_id = ?",
        (case_id,)
    )

    deleted = cursor.rowcount
    connection.commit()
    connection.close()
    return deleted > 0


def get_investigation_stats():
    """Return live dashboard statistics from SQLite."""
    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN UPPER(TRIM(prediction)) = 'PHISHING'
                THEN 1 ELSE 0 END) AS phishing,
            SUM(CASE WHEN UPPER(TRIM(prediction)) = 'SPAM'
                THEN 1 ELSE 0 END) AS spam,
            SUM(CASE WHEN UPPER(TRIM(prediction)) = 'SAFE'
                THEN 1 ELSE 0 END) AS safe,
            SUM(CASE WHEN UPPER(TRIM(threat_level)) = 'HIGH RISK'
                THEN 1 ELSE 0 END) AS high_risk,
            SUM(CASE WHEN UPPER(TRIM(threat_level)) = 'MEDIUM RISK'
                THEN 1 ELSE 0 END) AS medium_risk,
            SUM(CASE WHEN UPPER(TRIM(threat_level)) = 'LOW RISK'
                THEN 1 ELSE 0 END) AS low_risk,
            COALESCE(AVG(risk_score), 0) AS average_risk
        FROM investigations
    """)

    row = cursor.fetchone()
    connection.close()

    return {
        "total": row["total"] or 0,
        "phishing": row["phishing"] or 0,
        "spam": row["spam"] or 0,
        "safe": row["safe"] or 0,
        "high_risk": row["high_risk"] or 0,
        "medium_risk": row["medium_risk"] or 0,
        "low_risk": row["low_risk"] or 0,
        "average_risk": round(row["average_risk"] or 0, 1)
    }


if __name__ == "__main__":
    initialize_database()
    print("Database initialized successfully!")
    print("Database location:", DATABASE_PATH)
    print("Existing investigations:", len(get_all_investigations()))
