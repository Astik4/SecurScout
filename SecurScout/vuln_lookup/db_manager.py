import sqlite3
import json
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import List, Dict, Any, Optional

class DBManager:
    """Manages SQLite storage for CVE search caching and scan run execution history."""

    def __init__(self, db_path: str = "vulnerability_scanner.db"):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _connect(self):
        """Context manager to ensure database connections are closed properly."""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        """Initializes database schema tables if they do not exist."""
        with self._connect() as conn:
            cursor = conn.cursor()
            
            # Table 1: CVE lookup cache to avoid external API rate limits
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cache_key TEXT PRIMARY KEY,
                    cve_data TEXT NOT NULL,
                    cached_at TEXT NOT NULL
                )
            """)
            
            # Table 2: Historical scan metadata and full results
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    targets TEXT NOT NULL,
                    max_risk_score REAL NOT NULL,
                    results_json TEXT NOT NULL
                )
            """)
            conn.commit()

    # --- CVE Cache Operations ---

    def get_cached_cve(self, cache_key: str, max_age_days: int = 7) -> Optional[List[Dict[str, Any]]]:
        """
        Retrieves cached CVE data if it exists and is not older than max_age_days.
        Returns None on a cache miss or if the cache has expired.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT cve_data, cached_at FROM cve_cache WHERE cache_key = ?",
                (cache_key,)
            )
            row = cursor.fetchone()
            
            if not row:
                return None

            cve_json, cached_at_str = row
            try:
                cached_at = datetime.fromisoformat(cached_at_str)
                age = datetime.now(timezone.utc) - cached_at
                
                if age.days >= max_age_days:
                    return None  # Expired cache entry
                    
                return json.loads(cve_json)
            except Exception:
                # If there's any parsing or date error, treat it as a cache miss
                return None

    def save_cve_to_cache(self, cache_key: str, cve_data: List[Dict[str, Any]]):
        """Saves or updates CVE lookup results in the local cache table."""
        cve_json = json.dumps(cve_data)
        now_str = datetime.now(timezone.utc).isoformat()
        
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO cve_cache (cache_key, cve_data, cached_at)
                VALUES (?, ?, ?)
                """,
                (cache_key, cve_json, now_str)
            )
            conn.commit()

    # --- Scan History Operations ---

    def save_scan(
        self,
        scan_id: str,
        start_time: str,
        end_time: str,
        targets: List[str],
        max_risk_score: float,
        results: Dict[str, Any]
    ):
        """Logs a completed scan execution and its final report payload to the database."""
        targets_str = ", ".join(targets)
        results_json = json.dumps(results)
        
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scans (scan_id, start_time, end_time, targets, max_risk_score, results_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_id, start_time, end_time, targets_str, max_risk_score, results_json)
            )
            conn.commit()

    def get_scan_history(self) -> List[Dict[str, Any]]:
        """Returns a list of all logged scans (metadata only, excluding full results JSON)."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT scan_id, start_time, end_time, targets, max_risk_score
                FROM scans
                ORDER BY start_time DESC
                """
            )
            rows = cursor.fetchall()
            
            history = []
            for row in rows:
                history.append({
                    "scan_id": row[0],
                    "start_time": row[1],
                    "end_time": row[2],
                    "targets": row[3],
                    "max_risk_score": row[4]
                })
            return history

    def get_scan_details(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the full raw results JSON of a specific scan by its scan ID."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT results_json FROM scans WHERE scan_id = ?",
                (scan_id,)
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None
