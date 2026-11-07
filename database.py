import sqlite3
from datetime import datetime

DB_NAME = "phishguard.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            result_json TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_analysis(url, risk_level, result_json):
    conn = get_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat(timespec="seconds")
    cursor.execute(
        "INSERT INTO analysis (url, risk_level, result_json, timestamp) VALUES (?, ?, ?, ?)",
        (url, risk_level, result_json, timestamp)
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def get_history(limit=20):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, url, risk_level, timestamp FROM analysis ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()

    history = []
    for row in rows:
        history.append({
            "id": row[0],
            "url": row[1],
            "risk_level": row[2],
            "timestamp": row[3]
        })
    return history

def get_analysis_by_id(analysis_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, url, risk_level, result_json, timestamp FROM analysis WHERE id = ?",
        (analysis_id,)
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    return {
        "id": row[0],
        "url": row[1],
        "risk_level": row[2],
        "result": row[3],
        "timestamp": row[4]
    }

if __name__ == "__main__":
    init_db()
    print("Database ready!")