import json
import os
import sqlite3
import datetime


class AuditLogService:
    DB_PATH = os.getenv("FINSHIELD_DB_PATH", "data/finshield.db")

    @staticmethod
    def init_db():
        os.makedirs(os.path.dirname(AuditLogService.DB_PATH), exist_ok=True)
        with sqlite3.connect(AuditLogService.DB_PATH) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    username TEXT,
                    source TEXT NOT NULL,
                    url TEXT NOT NULL,
                    prediction INTEGER NOT NULL,
                    prob_phishing REAL NOT NULL,
                    risk TEXT NOT NULL,
                    features_json TEXT,
                    explain_json TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    username TEXT,
                    event TEXT NOT NULL,
                    details TEXT
                )
                """
            )
            conn.commit()

    @staticmethod
    def log_auth_event(username, event, details=None):
        AuditLogService.init_db()
        ts = datetime.datetime.utcnow().isoformat()
        with sqlite3.connect(AuditLogService.DB_PATH) as conn:
            conn.execute(
                "INSERT INTO auth_events (ts, username, event, details) VALUES (?, ?, ?, ?)",
                (ts, username, event, json.dumps(details) if details is not None else None),
            )
            conn.commit()

    @staticmethod
    def log_scan_event(username, source, url, prediction, prob_phishing, risk, features=None, explain=None):
        AuditLogService.init_db()
        ts = datetime.datetime.utcnow().isoformat()
        with sqlite3.connect(AuditLogService.DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO scan_events
                (ts, username, source, url, prediction, prob_phishing, risk, features_json, explain_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    username,
                    source,
                    url,
                    int(prediction),
                    float(prob_phishing),
                    str(risk),
                    json.dumps(features) if features is not None else None,
                    json.dumps(explain) if explain is not None else None,
                ),
            )
            conn.commit()

    @staticmethod
    def get_recent_scans(limit=100):
        AuditLogService.init_db()
        with sqlite3.connect(AuditLogService.DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM scan_events ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def get_recent_auth(limit=100):
        AuditLogService.init_db()
        with sqlite3.connect(AuditLogService.DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM auth_events ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

