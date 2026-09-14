import sqlite3
import json
from datetime import datetime

DB_NAME = "mailtrace.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT UNIQUE,
            filename TEXT,
            sender TEXT,
            receiver TEXT,
            subject TEXT,
            risk_score REAL,
            risk_level TEXT,
            analysis_json TEXT,
            created_at TEXT
        )
    """)

    # Upgrade existing databases created with the older schema
    cursor.execute("PRAGMA table_info(cases)")
    columns = [row[1] for row in cursor.fetchall()]

    if "analysis_json" not in columns:
        cursor.execute("""
            ALTER TABLE cases
            ADD COLUMN analysis_json TEXT
        """)

    conn.commit()
    conn.close()


def save_case(
    case_id,
    filename,
    sender,
    receiver,
    subject,
    risk_score,
    risk_level,
    analysis=None
):
    conn = get_connection()
    cursor = conn.cursor()

    analysis_json = None

    if analysis is not None:
        analysis_json = json.dumps(
            analysis,
            ensure_ascii=False
        )

    cursor.execute("""
        INSERT INTO cases (
            case_id,
            filename,
            sender,
            receiver,
            subject,
            risk_score,
            risk_level,
            analysis_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_id,
        filename,
        sender,
        receiver,
        subject,
        risk_score,
        risk_level,
        analysis_json,
        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()


def get_cases():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            case_id,
            filename,
            sender,
            receiver,
            subject,
            risk_score,
            risk_level,
            created_at
        FROM cases
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    cases = []

    for row in rows:
        cases.append({
            "case_id": row[0],
            "filename": row[1],
            "sender": row[2],
            "receiver": row[3],
            "subject": row[4],
            "risk_score": row[5],
            "risk_level": row[6],
            "created_at": row[7]
        })

    return cases


def get_case_by_id(case_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            case_id,
            filename,
            sender,
            receiver,
            subject,
            risk_score,
            risk_level,
            analysis_json,
            created_at
        FROM cases
        WHERE case_id = ?
    """, (case_id,))

    row = cursor.fetchone()

    conn.close()

    if not row:
        return None

    analysis = {}

    if row[7]:
        try:
            analysis = json.loads(row[7])
        except json.JSONDecodeError:
            analysis = {}

    if analysis:
        return analysis

    return {
        "case_id": row[0],
        "email": {
            "filename": row[1],
            "sender": row[2],
            "receiver": row[3],
            "subject": row[4]
        },
        "risk": {
            "score": row[5],
            "level": row[6]
        },
        "created_at": row[8]
    }