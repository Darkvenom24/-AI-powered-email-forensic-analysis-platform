import sqlite3
import json
from pathlib import Path
from datetime import datetime


# =========================================================
# DATABASE PATH
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "investigations.db"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():
    """
    Create and return a SQLite database connection.
    """

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    return connection


# =========================================================
# INITIALIZE DATABASE
# =========================================================

def initialize_database():
    """
    Create all required investigation tables.
    """

    connection = get_connection()
    cursor = connection.cursor()

    # -----------------------------------------------------
    # Investigations table
    # -----------------------------------------------------

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


# =========================================================
# CREATE CASE ID
# =========================================================

def generate_case_id():
    """
    Generate a unique investigation case ID.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM investigations"
    )

    count = cursor.fetchone()[0]

    connection.close()

    return f"CASE-{count + 1:04d}"


# =========================================================
# SAVE INVESTIGATION
# =========================================================

def save_investigation(result, sender="", receiver="", subject=""):
    """
    Save complete email investigation result.
    """

    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    case_id = generate_case_id()

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    prediction = result.get(
        "prediction",
        "UNKNOWN"
    )

    confidence = result.get(
        "confidence",
        0
    )

    risk_score = result.get(
        "risk_score",
        0
    )

    threat_level = result.get(
        "threat_level",
        "UNKNOWN"
    )

    risk_reasons = json.dumps(
        result.get("risk_reasons", []),
        default=str
    )

    forensic_data = json.dumps(
        result.get("forensics", {}),
        default=str
    )

    ioc_data = json.dumps(
        result.get("iocs", {}),
        default=str
    )

    attachment_data = json.dumps(
        result.get("attachments", {}),
        default=str
    )

    timeline_data = json.dumps(
        result.get("timeline", {}),
        default=str
    )

    cursor.execute("""
        INSERT INTO investigations (
            case_id,
            timestamp,
            sender,
            receiver,
            subject,
            prediction,
            confidence,
            risk_score,
            threat_level,
            risk_reasons,
            forensic_data,
            ioc_data,
            attachment_data,
            timeline_data
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
        risk_reasons,
        forensic_data,
        ioc_data,
        attachment_data,
        timeline_data
    ))

    connection.commit()
    connection.close()

    return case_id


# =========================================================
# GET ALL INVESTIGATIONS
# =========================================================

def get_all_investigations():
    """
    Return all investigation records.
    """

    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            case_id,
            timestamp,
            sender,
            receiver,
            subject,
            prediction,
            confidence,
            risk_score,
            threat_level
        FROM investigations
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return [dict(row) for row in rows]


# =========================================================
# GET SINGLE INVESTIGATION
# =========================================================

def get_investigation(case_id):
    """
    Return complete investigation by case ID.
    """

    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM investigations
        WHERE case_id = ?
    """, (case_id,))

    row = cursor.fetchone()

    connection.close()

    if row is None:
        return None

    result = dict(row)

    # Convert JSON strings back to Python objects

    for field in [
        "risk_reasons",
        "forensic_data",
        "ioc_data",
        "attachment_data",
        "timeline_data"
    ]:

        try:
            result[field] = json.loads(
                result[field]
            )
        except Exception:
            result[field] = {}

    return result


# =========================================================
# DELETE INVESTIGATION
# =========================================================

def delete_investigation(case_id):
    """
    Delete an investigation by case ID.
    """

    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM investigations
        WHERE case_id = ?
    """, (case_id,))

    deleted = cursor.rowcount

    connection.commit()
    connection.close()

    return deleted > 0


# =========================================================
# DATABASE TEST
# =========================================================

if __name__ == "__main__":

    print()
    print("======================================")
    print("   INVESTIGATION DATABASE TEST")
    print("======================================")

    initialize_database()

    print()
    print("Database initialized successfully!")
    print()
    print("Database location:")
    print(DATABASE_PATH)

    print()

    print(
        "Existing investigations:",
        len(get_all_investigations())
    )

    print()

    print("Database test completed successfully!")