"""SQLite storage and query helpers for captured network traffic."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent 
#resolve convert to absolute path, parent gets the contaning folder
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "traffic.db"

PACKET_COLUMNS = ( #tuple contaning column names for reference
    "captured_at",
    "source_mac",
    "destination_mac",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_size",
    "ether_type",
)


@contextmanager
def connection(database_path: str | Path = DEFAULT_DATABASE_PATH):
    """Yield a configured SQLite connection and close it when finished."""
    db_path = Path(database_path)
    if db_path != Path(":memory:"):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        #creates a parent directory if it is not exists
        #parents=True create missing parent directories too
        #exist_ok=True do not fail if the directory already exists

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row #changes query from tuples into row objects
    #without this r[0] but with this row["nenen"]
    conn.execute("PRAGMA foreign_keys = ON") #enales foreign keys
    conn.execute("PRAGMA busy_timeout = 5000")
    #sniffer may write while Streamlit is reading
    try:
        yield conn
    finally:
        conn.close()


def initialize_database(database_path: str | Path = DEFAULT_DATABASE_PATH) -> None: # None mean that it does not return any value
    """Create the database schema and indexes if they do not already exist."""
    with connection(database_path) as conn:
        conn.executescript(
            #WAL = Write-Ahead Logging.
            #synchronous = NORMAL -- Uses a good balance between write speed and durability.
            """
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                captured_at TEXT NOT NULL,
                source_mac TEXT,
                destination_mac TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                packet_size INTEGER NOT NULL CHECK (packet_size >= 0),
                ether_type INTEGER
            );

            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                captured_at TEXT NOT NULL,
                domain TEXT NOT NULL,
                query_type INTEGER,
                source_ip TEXT,
                destination_ip TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                source_mac TEXT,
                source_ip TEXT,
                packet_id INTEGER REFERENCES packets(id)
            );

            CREATE INDEX IF NOT EXISTS idx_packets_captured_at
                ON packets(captured_at);
            CREATE INDEX IF NOT EXISTS idx_packets_protocol
                ON packets(protocol);
            CREATE INDEX IF NOT EXISTS idx_packets_source_mac
                ON packets(source_mac);
            CREATE INDEX IF NOT EXISTS idx_dns_queries_domain
                ON dns_queries(domain);
            CREATE INDEX IF NOT EXISTS idx_alerts_created_at
                ON alerts(created_at);
            """
        )
        conn.commit()


def _timestamp(value: Any = None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    if isinstance(value, datetime):
        return value.isoformat(timespec="milliseconds")
    return str(value)


def _packet_values(packet: Mapping[str, Any]) -> tuple[Any, ...]:
    if not packet.get("protocol"):
        raise ValueError("A packet must include a non-empty protocol")
    if packet.get("packet_size") is None:
        raise ValueError("A packet must include packet_size")

    return (
        _timestamp(packet.get("captured_at")),
        packet.get("source_mac"),
        packet.get("destination_mac"),
        packet.get("source_ip"),
        packet.get("destination_ip"),
        packet["protocol"],
        packet.get("source_port"),
        packet.get("destination_port"),
        packet["packet_size"],
        packet.get("ether_type"),
    )


def insert_packet(
    packet: Mapping[str, Any],
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Insert one packet record and return its database id."""
    with connection(database_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO packets (
                captured_at, source_mac, destination_mac, source_ip,
                destination_ip, protocol, source_port, destination_port,
                packet_size, ether_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            #placeholder for sql injections
            _packet_values(packet),
        )
        conn.commit()
        return int(cursor.lastrowid)


def insert_packets(
    packets: Iterable[Mapping[str, Any]],
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Insert packet records in one transaction and return the inserted count."""
    values = [_packet_values(packet) for packet in packets]
    if not values:
        return 0

    with connection(database_path) as conn:
        conn.executemany(
            """
            INSERT INTO packets (
                captured_at, source_mac, destination_mac, source_ip,
                destination_ip, protocol, source_port, destination_port,
                packet_size, ether_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        conn.commit()
    return len(values)


def insert_dns_query(
    query: Mapping[str, Any],
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Insert a DNS query record and return its database id."""
    if not query.get("domain"):
        raise ValueError("A DNS query must include a non-empty domain")

    with connection(database_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO dns_queries (
                captured_at, domain, query_type, source_ip, destination_ip
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                _timestamp(query.get("captured_at")),
                query["domain"],
                query.get("query_type"),
                query.get("source_ip"),
                query.get("destination_ip"),
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def insert_alert(
    alert: Mapping[str, Any],
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Insert an alert record and return its database id."""
    required = ("alert_type", "severity", "message")
    missing = [field for field in required if not alert.get(field)]
    if missing:
        raise ValueError(f"An alert is missing required fields: {', '.join(missing)}")

    with connection(database_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO alerts (
                created_at, alert_type, severity, message,
                source_mac, source_ip, packet_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _timestamp(alert.get("created_at")),
                alert["alert_type"],
                alert["severity"],
                alert["message"],
                alert.get("source_mac"),
                alert.get("source_ip"),
                alert.get("packet_id"),
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def _rows(
    query: str,
    parameters: tuple[Any, ...] = (),
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[dict[str, Any]]:
    with connection(database_path) as conn:
        return [dict(row) for row in conn.execute(query, parameters).fetchall()]


def get_recent_packets(
    limit: int = 100,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[dict[str, Any]]:
    """Return the newest packet records first."""
    if limit < 1:
        raise ValueError("limit must be greater than zero")
    return _rows(
        """
        SELECT *
        FROM packets
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
        database_path,
    )


def get_protocol_counts(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[dict[str, Any]]:
    return _rows(
        """
        SELECT protocol, COUNT(*) AS packet_count
        FROM packets
        GROUP BY protocol
        ORDER BY packet_count DESC, protocol
        """,
        database_path=database_path,
    )


def get_top_source_macs(
    limit: int = 10,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[dict[str, Any]]:
    if limit < 1:
        raise ValueError("limit must be greater than zero")
    return _rows(
        """
        SELECT source_mac, COUNT(*) AS packet_count, SUM(packet_size) AS byte_count
        FROM packets
        WHERE source_mac IS NOT NULL
        GROUP BY source_mac
        ORDER BY byte_count DESC, source_mac
        LIMIT ?
        """,
        (limit,),
        database_path,
    )


def get_top_dns_domains(
    limit: int = 10,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[dict[str, Any]]:
    if limit < 1:
        raise ValueError("limit must be greater than zero")
    return _rows(
        """
        SELECT domain, COUNT(*) AS query_count
        FROM dns_queries
        GROUP BY domain
        ORDER BY query_count DESC, domain
        LIMIT ?
        """,
        (limit,),
        database_path,
    )


def get_dns_domains(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[dict[str, Any]]:
    """Return every queried DNS domain ordered by query count."""
    return _rows(
        """
        SELECT domain, COUNT(*) AS query_count
        FROM dns_queries
        GROUP BY domain
        ORDER BY query_count DESC, domain
        """,
        database_path=database_path,
    )


def get_traffic_over_time(
    interval: str = "minute",
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[dict[str, Any]]:
    """Return packet and byte totals grouped into minute or hour buckets."""
    if interval not in {"minute", "hour"}:
        raise ValueError("interval must be either 'minute' or 'hour'")

    bucket_format = "%Y-%m-%dT%H:%M:00" if interval == "minute" else "%Y-%m-%dT%H:00:00"
    return _rows(
        f"""
        SELECT
            strftime('{bucket_format}', captured_at) AS time_bucket,
            COUNT(*) AS packet_count,
            COALESCE(SUM(packet_size), 0) AS byte_count
        FROM packets
        GROUP BY time_bucket
        ORDER BY time_bucket
        """,
        database_path=database_path,
    )


def get_summary(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> dict[str, int]:
    """Return the aggregate counters used by dashboard metric cards."""
    with connection(database_path) as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS total_packets,
                   COALESCE(SUM(packet_size), 0) AS total_bytes
            FROM packets
            """
        ).fetchone()
    return {
        "total_packets": int(row["total_packets"]),
        "total_bytes": int(row["total_bytes"]),
    }


def get_recent_alerts(
    limit: int = 50,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[dict[str, Any]]:
    if limit < 1:
        raise ValueError("limit must be greater than zero")
    return _rows(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
        database_path,
    )


if __name__ == "__main__":
    initialize_database()
    print(f"Initialized {DEFAULT_DATABASE_PATH}")
