import json
import sqlite3
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class Alert:
    id: str
    risk_score: float
    severity: str
    findings: List[dict]
    url: str
    host: str
    path: Optional[str]
    method: Optional[str]
    timestamp: str
    acknowledged: bool = False


class AlertManager:
    def __init__(self, config: dict):
        self.config = config
        db_path = config.get("alerts", {}).get("db_path", "/data/alerts.db")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_db()
        self._counter = self._load_counter()

    def _init_db(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                risk_score REAL NOT NULL,
                severity TEXT NOT NULL,
                findings TEXT NOT NULL,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT,
                method TEXT,
                timestamp TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
            CREATE TABLE IF NOT EXISTS entities (
                host TEXT PRIMARY KEY,
                requests INTEGER NOT NULL DEFAULT 0,
                alerts INTEGER NOT NULL DEFAULT 0,
                risk REAL NOT NULL DEFAULT 0.0,
                last_seen TEXT NOT NULL DEFAULT ''
            );
        """)
        self._conn.commit()

    def _load_counter(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) as cnt FROM alerts").fetchone()
        return row["cnt"] if row else 0

    def trigger(self, data: dict) -> Alert:
        with self._lock:
            self._counter += 1
            alert = Alert(
                id=f"ALERT-{self._counter:06d}",
                risk_score=data.get("risk_score", 0.0),
                severity=data.get("severity", "low"),
                findings=data.get("findings", []),
                url=data.get("url", ""),
                host=data.get("host", ""),
                path=data.get("path"),
                method=data.get("method"),
                timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            )
            self._conn.execute(
                """INSERT INTO alerts (id, risk_score, severity, findings, url, host, path, method, timestamp, acknowledged, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)""",
                (
                    alert.id,
                    alert.risk_score,
                    alert.severity,
                    json.dumps(alert.findings),
                    alert.url,
                    alert.host,
                    alert.path,
                    alert.method,
                    alert.timestamp,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._update_entity(alert.host, alert.risk_score, alert.timestamp)
            self._conn.commit()

            if self.config.get("alerts", {}).get("file", False):
                self._write_to_file(alert)

            return alert

    def _update_entity(self, host: str, risk_score: float, timestamp: str):
        existing = self._conn.execute(
            "SELECT requests, alerts, risk FROM entities WHERE host = ?", (host,)
        ).fetchone()
        if existing:
            self._conn.execute(
                "UPDATE entities SET requests = requests + 1, alerts = alerts + 1, risk = MAX(risk, ?), last_seen = ? WHERE host = ?",
                (risk_score, timestamp, host),
            )
        else:
            self._conn.execute(
                "INSERT INTO entities (host, requests, alerts, risk, last_seen) VALUES (?, 1, 1, ?, ?)",
                (host, risk_score, timestamp),
            )

    def update_entity_traffic(self, host: str, timestamp: Optional[str] = None):
        with self._lock:
            existing = self._conn.execute(
                "SELECT host FROM entities WHERE host = ?", (host,)
            ).fetchone()
            if existing:
                self._conn.execute(
                    "UPDATE entities SET requests = requests + 1 WHERE host = ?", (host,)
                )
                if timestamp:
                    self._conn.execute(
                        "UPDATE entities SET last_seen = ? WHERE host = ?", (timestamp, host)
                    )
            else:
                self._conn.execute(
                    "INSERT INTO entities (host, requests, alerts, risk, last_seen) VALUES (?, 1, 0, 0.0, ?)",
                    (host, timestamp or ""),
                )
            self._conn.commit()

    def get_entities(self) -> List[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM entities ORDER BY risk DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def _write_to_file(self, alert: Alert):
        file_path = self.config.get("alerts", {}).get("file_path", "/data/alerts.log")
        try:
            with open(file_path, "a") as f:
                f.write(json.dumps(asdict(alert)) + "\n")
        except OSError as e:
            print(f"Failed to write alert to file: {e}")

    def get_alerts(self, severity: Optional[str] = None, limit: int = 100) -> List[Alert]:
        with self._lock:
            if severity:
                rows = self._conn.execute(
                    "SELECT * FROM alerts WHERE severity = ? ORDER BY created_at DESC LIMIT ?",
                    (severity, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
            return [self._row_to_alert(r) for r in rows]

    def clear(self):
        with self._lock:
            self._conn.execute("DELETE FROM alerts")
            self._conn.execute("DELETE FROM entities")
            self._conn.commit()
            self._counter = 0

    def acknowledge(self, alert_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ? AND acknowledged = 0",
                (alert_id,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def stats(self) -> dict:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) as cnt FROM alerts").fetchone()["cnt"]
            by_severity = {}
            for row in self._conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
            ).fetchall():
                by_severity[row["severity"]] = row["cnt"]
            unacked = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM alerts WHERE acknowledged = 0"
            ).fetchone()["cnt"]
            return {
                "total_alerts": total,
                "by_severity": by_severity,
                "unacknowledged": unacked,
            }

    def _row_to_alert(self, row: sqlite3.Row) -> Alert:
        return Alert(
            id=row["id"],
            risk_score=row["risk_score"],
            severity=row["severity"],
            findings=json.loads(row["findings"]),
            url=row["url"],
            host=row["host"],
            path=row["path"],
            method=row["method"],
            timestamp=row["timestamp"],
            acknowledged=bool(row["acknowledged"]),
        )

    def close(self):
        self._conn.close()
