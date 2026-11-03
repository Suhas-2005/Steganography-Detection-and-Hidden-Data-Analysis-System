"""
StegAnalyzer — Investigation history management.

Provides persistence and retrieval of previous forensic investigations
using a lightweight local SQLite database and in-session caching.
Sensitive raw image bytes are never persisted in the history store.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from utils.config import PROJECT_ROOT

# SQLite database path
DB_PATH: Path = PROJECT_ROOT / "history.sqlite"


def init_db() -> None:
    """Initialize the SQLite database schema if not present."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                investigation_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size_str TEXT NOT NULL,
                dimensions TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                findings_summary TEXT NOT NULL,
                full_results_json TEXT NOT NULL
            )
            """
        )
        conn.commit()


def add_investigation(record: dict[str, Any]) -> None:
    """Store an investigation record in the database."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO investigations (
                investigation_id,
                timestamp,
                filename,
                file_type,
                file_size_str,
                dimensions,
                sha256,
                status,
                findings_summary,
                full_results_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["investigation_id"],
                record.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")),
                record.get("filename", "Unknown"),
                record.get("file_type", "Unknown"),
                record.get("file_size_str", "Unknown"),
                record.get("dimensions", "Unknown"),
                record.get("sha256", "Unknown"),
                record.get("status", "Analysis completed"),
                record.get("findings_summary", ""),
                json.dumps(record.get("full_results", {})),
            ),
        )
        conn.commit()


def get_all_investigations() -> list[dict[str, Any]]:
    """Retrieve all investigation records in reverse chronological order."""
    init_db()
    results = []
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT investigation_id, timestamp, filename, file_type,
                   file_size_str, dimensions, sha256, status, findings_summary, full_results_json
            FROM investigations
            ORDER BY timestamp DESC
            """
        )
        for row in cursor.fetchall():
            results.append({
                "investigation_id": row["investigation_id"],
                "timestamp": row["timestamp"],
                "filename": row["filename"],
                "file_type": row["file_type"],
                "file_size_str": row["file_size_str"],
                "dimensions": row["dimensions"],
                "sha256": row["sha256"],
                "status": row["status"],
                "findings_summary": row["findings_summary"],
                "full_results": json.loads(row["full_results_json"]) if row["full_results_json"] else {},
            })
    return results


def get_investigation_by_id(investigation_id: str) -> Optional[dict[str, Any]]:
    """Retrieve a single investigation by its unique ID."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT investigation_id, timestamp, filename, file_type,
                   file_size_str, dimensions, sha256, status, findings_summary, full_results_json
            FROM investigations
            WHERE investigation_id = ?
            """,
            (investigation_id,),
        )
        row = cursor.fetchone()
        if row:
            return {
                "investigation_id": row["investigation_id"],
                "timestamp": row["timestamp"],
                "filename": row["filename"],
                "file_type": row["file_type"],
                "file_size_str": row["file_size_str"],
                "dimensions": row["dimensions"],
                "sha256": row["sha256"],
                "status": row["status"],
                "findings_summary": row["findings_summary"],
                "full_results": json.loads(row["full_results_json"]) if row["full_results_json"] else {},
            }
    return None


def get_session_statistics(session_records: list[dict[str, Any]]) -> dict[str, int]:
    """Calculate statistics based on session records.

    Returns
    -------
    dict:
      - total_analyzed
      - suspicious_count
      - extracted_count
      - clean_count
    """
    total = len(session_records)
    suspicious = 0
    extracted = 0
    clean = 0

    for rec in session_records:
        status = rec.get("status", "").lower()
        if "extracted" in status:
            extracted += 1
        elif "indicator" in status or "suspicious" in status:
            suspicious += 1
        else:
            clean += 1

    return {
        "total_analyzed": total,
        "suspicious_count": suspicious,
        "extracted_count": extracted,
        "clean_count": clean,
    }


def clear_all_history() -> None:
    """Clear all stored history records."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM investigations")
        conn.commit()

