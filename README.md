# 🛡️ SIH26106: AI-Powered Email Forensic Analysis Platform

> **Smart India Hackathon (SIH26106)**: AI-Powered Email Threat Detection, Geolocation Tracking, and Forensic Intelligence Platform.

![Dashboard Preview](https://img.shields.io/badge/SIH-2026-blue?style=for-the-badge) ![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python) ![FastAPI%20%2F%20Flask](https://img.shields.io/badge/Backend-Flask%20%2B%20REST%20API-teal?style=for-the-badge) ![Supabase](https://img.shields.io/badge/Database-Supabase%20PostgreSQL-green?style=for-the-badge&logo=supabase) ![Vercel](https://img.shields.io/badge/Deploy-Vercel%20Ready-black?style=for-the-badge&logo=vercel)

---

## 🚀 Overview

This platform goes beyond conventional spam/phishing filters. It provides **in-depth forensic attribution** answering:
- **Is this email malicious?** (Multi-signal AI text classifier + heuristic rules)
- **Why is it malicious?** (Explainable breakdown: SPF/DKIM/DMARC status, From/Reply-To mismatch, URL risk, and executable attachments)
- **Where did it come from?** (Mail relay path parsing + approximate IP geolocation visualized on an interactive dark world map)
- **How does everything connect?** (Interactive entity relationship graph: Sender ➔ Domain ➔ Relay IP ➔ Malicious URL ➔ Payload)
- **What is the chronological sequence of events?** (Forensic timeline reconstruction)
- **Exportable Evidence**: One-click download of high-resolution digital forensic PDF reports suitable for SIEM and law enforcement submission.

---

## 🖥️ User Interface (Matching SIH Mockup)

The interface is built with a high-performance **Cyber SOC Analyst dark theme**:
- **Speedometer Threat Score Gauge**: Dynamic 0–100 risk arc with real-time High / Medium / Low risk badge.
- **Entity Cards**: Originating Sender (with spoofing alerts), Recipient, Domain, and URLs.
- **Phishing Probability & Threat Spectrum**: Gradient progress bar with audio-frequency style threat wave.
- **Threat Indicators**: Cyber alert pills (SPF Failed, Reply-To Mismatch, Raw IP URL, Risky Attachment).
- **IP Intelligence & Leaflet Map**: Dark Matter map showing sender and relay coordinates.
- **Forensic Timeline**: Chronological vertical event sequence with step timestamps.
- **Interactive Relationship Graph**: Node graph linking Sender ➔ Domain ➔ IP ➔ URL ➔ Attachment.
- **1-Click Judge Presets**: Instant evaluation cases (Fake Invoice Phishing, Account Suspension, CEO Fraud BEC, Safe Meeting).

---

## 🗄️ Database Strategy: Supabase + Local Fallback

### Dual-Mode Persistence
- **Cloud Mode (Supabase)**: Connects to your managed Supabase PostgreSQL instance for persistent, multi-analyst history on Vercel serverless deployments.
- **Local Fallback (SQLite)**: Automatically falls back to local `data/investigations.db` when offline or during initial setup.
- **1-Click Sync**: Local cases can be migrated to Supabase with one click in the web UI.

### Supabase Setup
1. Create a free project on [Supabase](https://supabase.com).
2. Open the **SQL Editor** in your Supabase dashboard.
3. Paste and run the contents of [`supabase_schema.sql`](./supabase_schema.sql).
4. Enter your `SUPABASE_URL` and `SUPABASE_KEY` either:
   - In your `.env` file (see [`.env.example`](./.env.example)), or
   - Directly in the web interface via **Settings & Supabase**.

---

## ⚙️ Quickstart (Running Locally)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)
```bash
cp .env.example .env
# Edit .env with your Supabase URL and Key if available
```

### 3. Start the Platform
```bash
python app.py
```
Open your browser at **`http://localhost:5000`**.

---

## 🌐 Deploying to Vercel

The platform is pre-configured with `vercel.json` for deployment to Vercel.

### Via Vercel CLI:
```bash
npm install -g vercel
vercel
```

### Via GitHub:
1. Push this repository to GitHub.
2. Import the repository in your [Vercel Dashboard](https://vercel.com).
3. Under **Environment Variables**, add:
   - `SUPABASE_URL`: Your Supabase Project URL
   - `SUPABASE_KEY`: Your Supabase Anon/Service Key
   - `FLASK_SECRET_KEY`: Any secure random string
4. Click **Deploy**!

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Ingest `.eml` file or raw text; returns full forensic JSON |
| `GET` | `/api/presets` | Get pre-packaged demonstration sample emails |
| `POST` | `/api/preset/<id>` | Run analysis directly on a preset case |
| `GET` | `/api/history` | List previous investigation cases |
| `GET` | `/api/case/<id>` | Retrieve full details of a specific case |
| `GET` | `/api/stats` | Aggregated threat stats & database mode |
| `GET` | `/api/export-report` | Generate and download ReportLab PDF report |
| `GET` | `/api/supabase-status`| Check Supabase connection health |
| `POST` | `/api/settings` | Update Supabase credentials dynamically |
| `POST` | `/api/sync-supabase` | Migrate local SQLite records into Supabase |
