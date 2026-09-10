import sqlite3
import json
from pathlib import Path
from datetime import datetime

# Supabase integration
try:
    from src.supabase_client import (
        is_supabase_configured,
        save_investigation_supabase,
        get_all_investigations_supabase,
        get_investigation_supabase,
        get_investigation_stats_supabase
    )
except ImportError:
    from supabase_client import (
        is_supabase_configured,
        save_investigation_supabase,
        get_all_investigations_supabase,
        get_investigation_supabase,
        get_investigation_stats_supabase
    )

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
    """
    Save investigation to SQLite and simultaneously to Supabase if configured.
    """
    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    case_id = generate_case_id()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    prediction = result.get("prediction", "UNKNOWN")
    confidence = result.get("confidence", 0)
    risk_score = result.get("risk_score", 0)

    # Accept both names so old/new analysis results work.
    threat_level = result.get(
        "threat_level",
        result.get("threat", "UNKNOWN")
    )

    risk_reasons_json = json.dumps(result.get("risk_reasons", []), default=str)
    forensic_data_json = json.dumps(result.get("forensics", {}), default=str)
    ioc_data_json = json.dumps(result.get("iocs", {}), default=str)
    attachment_data_json = json.dumps(result.get("attachments", {}), default=str)
    timeline_data_json = json.dumps(result.get("timeline", []), default=str)

    values = (
        case_id,
        timestamp,
        sender,
        receiver,
        subject,
        prediction,
        confidence,
        risk_score,
        threat_level,
        risk_reasons_json,
        forensic_data_json,
        ioc_data_json,
        attachment_data_json,
        timeline_data_json
    )

    cursor.execute("""
        INSERT INTO investigations (
            case_id, timestamp, sender, receiver, subject,
            prediction, confidence, risk_score, threat_level,
            risk_reasons, forensic_data, ioc_data,
            attachment_data, timeline_data
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, values)

    connection.commit()
    connection.close()

    # Cloud sync to Supabase if configured
    if is_supabase_configured():
        try:
            save_investigation_supabase({
                "case_id": case_id,
                "timestamp": timestamp,
                "sender": sender,
                "receiver": receiver,
                "subject": subject,
                "prediction": prediction,
                "confidence": confidence,
                "risk_score": risk_score,
                "threat_level": threat_level,
                "risk_reasons": result.get("risk_reasons", []),
                "forensic_data": result.get("forensics", {}),
                "ioc_data": result.get("iocs", {}),
                "attachment_data": result.get("attachments", {}),
                "timeline_data": result.get("timeline", []),
            })
        except Exception as e:
            print(f"Notice: Saved to SQLite, but Supabase sync failed: {e}")

    return case_id


def get_all_investigations():
    """
    Retrieve investigations. If Supabase is active, fetch from cloud,
    otherwise fallback to local SQLite.
    """
    if is_supabase_configured():
        try:
            cloud_records = get_all_investigations_supabase()
            if cloud_records:
                return cloud_records
        except Exception as e:
            print(f"Supabase fetch failed, falling back to SQLite: {e}")

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
    """
    Retrieve single case. Check Supabase first, fallback to SQLite.
    """
    if is_supabase_configured():
        try:
            cloud_case = get_investigation_supabase(case_id)
            if cloud_case:
                return cloud_case
        except Exception as e:
            print(f"Supabase case fetch error, checking SQLite: {e}")

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
            result[field] = [] if field in (
                "risk_reasons", "timeline_data"
            ) else {}

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
    """Return live dashboard statistics from Supabase or SQLite."""
    if is_supabase_configured():
        try:
            cloud_stats = get_investigation_stats_supabase()
            if cloud_stats and cloud_stats.get("total", 0) > 0:
                return cloud_stats
        except Exception as e:
            print(f"Supabase stats error: {e}")

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


def sync_sqlite_to_supabase():
    """
    Export all local SQLite investigation records to Supabase.
    Returns (synced_count: int, error_msg: str or None).
    """
    if not is_supabase_configured():
        return 0, "Supabase is not configured. Please set SUPABASE_URL and SUPABASE_KEY."

    initialize_database()
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM investigations ORDER BY id ASC")
    rows = cursor.fetchall()
    connection.close()

    synced = 0
    for row in rows:
        r = dict(row)
        for field in ["risk_reasons", "forensic_data", "ioc_data", "attachment_data", "timeline_data"]:
            try:
                r[field] = json.loads(r[field])
            except Exception:
                r[field] = [] if "reasons" in field or "timeline" in field else {}

        success = save_investigation_supabase(r)
        if success:
            synced += 1

    return synced, None


if __name__ == "__main__":
    initialize_database()
    print("Database initialized successfully!")
    print("Database location:", DATABASE_PATH)
    print("Existing investigations:", len(get_all_investigations()))
    print("Supabase active:", is_supabase_configured())
