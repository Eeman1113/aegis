"""SQLite persistence for regression test runs and results."""

import sqlite3
import json
from datetime import datetime
from config import DB_PATH


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = _connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS test_suites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS test_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            suite_id INTEGER REFERENCES test_suites(id),
            quarter TEXT NOT NULL,
            year INTEGER NOT NULL,
            environment TEXT NOT NULL,
            region TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING',
            started_at TEXT,
            completed_at TEXT,
            triggered_by TEXT DEFAULT 'manual',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER REFERENCES test_runs(id),
            test_name TEXT NOT NULL,
            category TEXT NOT NULL,
            status TEXT NOT NULL,
            duration_seconds REAL,
            details TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Test suites
# ---------------------------------------------------------------------------

def create_test_suite(name: str, category: str, description: str = "") -> int:
    conn = _connect()
    cur = conn.execute(
        "INSERT INTO test_suites (name, category, description) VALUES (?, ?, ?)",
        (name, category, description),
    )
    conn.commit()
    suite_id = cur.lastrowid
    conn.close()
    return suite_id


def get_test_suites() -> list[dict]:
    conn = _connect()
    rows = conn.execute("SELECT * FROM test_suites ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_test_suite(suite_id: int):
    conn = _connect()
    conn.execute("DELETE FROM test_results WHERE run_id IN (SELECT id FROM test_runs WHERE suite_id = ?)", (suite_id,))
    conn.execute("DELETE FROM test_runs WHERE suite_id = ?", (suite_id,))
    conn.execute("DELETE FROM test_suites WHERE id = ?", (suite_id,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Test runs
# ---------------------------------------------------------------------------

def create_test_run(suite_id: int, quarter: str, year: int, environment: str, region: str, triggered_by: str = "manual") -> int:
    conn = _connect()
    cur = conn.execute(
        "INSERT INTO test_runs (suite_id, quarter, year, environment, region, status, started_at, triggered_by) VALUES (?, ?, ?, ?, ?, 'RUNNING', ?, ?)",
        (suite_id, quarter, year, environment, region, datetime.utcnow().isoformat(), triggered_by),
    )
    conn.commit()
    run_id = cur.lastrowid
    conn.close()
    return run_id


def complete_test_run(run_id: int, status: str):
    conn = _connect()
    conn.execute(
        "UPDATE test_runs SET status = ?, completed_at = ? WHERE id = ?",
        (status, datetime.utcnow().isoformat(), run_id),
    )
    conn.commit()
    conn.close()


def get_test_runs(suite_id: int | None = None, quarter: str | None = None, year: int | None = None) -> list[dict]:
    conn = _connect()
    query = """
        SELECT tr.*, ts.name as suite_name, ts.category as suite_category
        FROM test_runs tr
        JOIN test_suites ts ON tr.suite_id = ts.id
        WHERE 1=1
    """
    params = []
    if suite_id:
        query += " AND tr.suite_id = ?"
        params.append(suite_id)
    if quarter:
        query += " AND tr.quarter = ?"
        params.append(quarter)
    if year:
        query += " AND tr.year = ?"
        params.append(year)
    query += " ORDER BY tr.created_at DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Test results
# ---------------------------------------------------------------------------

def add_test_result(run_id: int, test_name: str, category: str, status: str, duration: float = 0, details: str = ""):
    conn = _connect()
    conn.execute(
        "INSERT INTO test_results (run_id, test_name, category, status, duration_seconds, details) VALUES (?, ?, ?, ?, ?, ?)",
        (run_id, test_name, category, status, duration, details),
    )
    conn.commit()
    conn.close()


def get_test_results(run_id: int) -> list[dict]:
    conn = _connect()
    rows = conn.execute("SELECT * FROM test_results WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_results_summary() -> list[dict]:
    """Aggregate pass/fail counts grouped by quarter, year, category."""
    conn = _connect()
    rows = conn.execute("""
        SELECT
            tr.quarter, tr.year, tr.environment,
            tres.category,
            COUNT(*) as total,
            SUM(CASE WHEN tres.status = 'PASSED' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN tres.status = 'FAILED' THEN 1 ELSE 0 END) as failed,
            AVG(tres.duration_seconds) as avg_duration
        FROM test_results tres
        JOIN test_runs tr ON tres.run_id = tr.id
        GROUP BY tr.quarter, tr.year, tr.environment, tres.category
        ORDER BY tr.year DESC, tr.quarter DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]
