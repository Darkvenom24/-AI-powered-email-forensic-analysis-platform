import os
import json
from datetime import datetime
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

# Initialize Supabase client lazily
_supabase_client = None
_client_initialized = False


def get_supabase_credentials():
    """Retrieve Supabase URL and Key from environment."""
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_KEY", "") or os.environ.get("SUPABASE_ANON_KEY", "").strip()
    return url, key


def is_supabase_configured():
    """Check if valid-looking Supabase credentials are configured."""
    url, key = get_supabase_credentials()
    if not url or not key:
        return False
    if "your-project" in url or "supabase.co" not in url:
        return False
    return True


def get_supabase_client():
    """Returns the Supabase client instance or None if not configured."""
    global _supabase_client, _client_initialized

    url, key = get_supabase_credentials()
    if not is_supabase_configured():
        return None

    try:
        from supabase import create_client, Client
        _supabase_client = create_client(url, key)
        _client_initialized = True
        return _supabase_client
    except Exception as e:
        print(f"Warning: Could not initialize Supabase client: {e}")
        return None


def test_connection():
    """Test connecting to Supabase and return (success: bool, message: str)."""
    client = get_supabase_client()
    if not client:
        return False, "Supabase credentials are not configured or invalid."

    try:
        # Simple read check on platform_settings or investigations
        res = client.table("investigations").select("case_id").limit(1).execute()
        return True, "Successfully connected to Supabase PostgreSQL database!"
    except Exception as e:
        err_msg = str(e)
        if "relation" in err_msg and "does not exist" in err_msg:
            return False, "Connected to Supabase, but tables are missing. Please run supabase_schema.sql in the Supabase SQL Editor."
        return False, f"Supabase connection failed: {err_msg}"


def save_investigation_supabase(case_dict):
    """Save investigation record into Supabase."""
    client = get_supabase_client()
    if not client:
        return False

    try:
        row = {
            "case_id": case_dict.get("case_id"),
            "timestamp": case_dict.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sender": case_dict.get("sender", ""),
            "receiver": case_dict.get("receiver", ""),
            "subject": case_dict.get("subject", ""),
            "prediction": case_dict.get("prediction", "UNKNOWN"),
            "confidence": float(case_dict.get("confidence", 0)),
            "risk_score": int(case_dict.get("risk_score", 0)),
            "threat_level": case_dict.get("threat_level") or case_dict.get("threat", "UNKNOWN"),
            "risk_reasons": case_dict.get("risk_reasons", []),
            "forensic_data": case_dict.get("forensics", case_dict.get("forensic_data", {})),
            "ioc_data": case_dict.get("iocs", case_dict.get("ioc_data", {})),
            "attachment_data": case_dict.get("attachments", case_dict.get("attachment_data", {})),
            "timeline_data": case_dict.get("timeline", case_dict.get("timeline_data", [])),
        }

        client.table("investigations").upsert(row, on_conflict="case_id").execute()
        return True
    except Exception as e:
        print(f"Failed to save to Supabase: {e}")
        return False


def get_all_investigations_supabase():
    """Retrieve all investigations from Supabase ordered by newest first."""
    client = get_supabase_client()
    if not client:
        return []

    try:
        res = client.table("investigations").select(
            "id, case_id, timestamp, sender, receiver, subject, prediction, confidence, risk_score, threat_level"
        ).order("id", desc=True).execute()
        return res.data or []
    except Exception as e:
        print(f"Error fetching investigations from Supabase: {e}")
        return []


def get_investigation_supabase(case_id):
    """Retrieve full details of an investigation by case_id."""
    client = get_supabase_client()
    if not client:
        return None

    try:
        res = client.table("investigations").select("*").eq("case_id", case_id).limit(1).execute()
        if res.data and len(res.data) > 0:
            return res.data[0]
        return None
    except Exception as e:
        print(f"Error fetching case {case_id} from Supabase: {e}")
        return None


def get_investigation_stats_supabase():
    """Calculate aggregated stats from Supabase investigations."""
    client = get_supabase_client()
    if not client:
        return None

    try:
        res = client.table("investigations").select("prediction, threat_level, risk_score").execute()
        rows = res.data or []
        total = len(rows)
        if total == 0:
            return {
                "total": 0, "phishing": 0, "spam": 0, "safe": 0,
                "high_risk": 0, "medium_risk": 0, "low_risk": 0,
                "average_risk": 0.0
            }

        phishing = sum(1 for r in rows if str(r.get("prediction", "")).strip().upper() == "PHISHING")
        spam = sum(1 for r in rows if str(r.get("prediction", "")).strip().upper() == "SPAM")
        safe = sum(1 for r in rows if str(r.get("prediction", "")).strip().upper() == "SAFE")
        high_risk = sum(1 for r in rows if "HIGH" in str(r.get("threat_level", "")).upper())
        medium_risk = sum(1 for r in rows if "MEDIUM" in str(r.get("threat_level", "")).upper())
        low_risk = sum(1 for r in rows if "LOW" in str(r.get("threat_level", "")).upper())
        avg_risk = sum(int(r.get("risk_score", 0) or 0) for r in rows) / total

        return {
            "total": total,
            "phishing": phishing,
            "spam": spam,
            "safe": safe,
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk,
            "average_risk": round(avg_risk, 1)
        }
    except Exception as e:
        print(f"Error calculating stats from Supabase: {e}")
        return None
