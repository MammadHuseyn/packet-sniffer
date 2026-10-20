"""Streamlit dashboard for the packet sniffer database."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import streamlit as st

import database


REFRESH_INTERVAL = "2s"
DEFAULT_PACKET_LIMIT = 100


def format_bytes(byte_count: int | float) -> str:
    """Format a byte count using a readable unit."""
    amount = float(byte_count)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or unit == "TB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TB"


def packets_per_second(traffic: list[dict[str, Any]]) -> float:
    """Estimate packets per second from the most recent minute bucket."""
    if not traffic:
        return 0.0
    return float(traffic[-1]["packet_count"]) / 60


def _display_packet_columns(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the packet fields that are useful in the dashboard table."""
    return [
        {
            "Time": packet["captured_at"],
            "Source": packet["source_ip"] or packet["source_mac"] or "-",
            "Destination": packet["destination_ip"]
            or packet["destination_mac"]
            or "-",
            "Protocol": packet["protocol"],
            "Ports": _format_ports(packet),
            "Size": format_bytes(packet["packet_size"]),
        }
        for packet in packets
    ]


def _format_ports(packet: dict[str, Any]) -> str:
    source_port = packet["source_port"]
    destination_port = packet["destination_port"]
    if source_port is None or destination_port is None:
        return "-"
    return f"{source_port} -> {destination_port}"


@st.fragment(run_every=REFRESH_INTERVAL)
def _render_dashboard(database_path: Path, packet_limit: int) -> None:
    """Render one dashboard refresh."""
    try:
        summary = database.get_summary(database_path)
        traffic = database.get_traffic_over_time("minute", database_path)
        protocols = database.get_protocol_counts(database_path)
        source_macs = database.get_top_source_macs(10, database_path)
        dns_domains = database.get_dns_domains(database_path)
        packets = database.get_recent_packets(
            packet_limit,
            database_path,
        )
        alerts = database.get_recent_alerts(10, database_path)
    except sqlite3.Error as error:
        st.error(f"Could not read the traffic database: {error}")
        return

    total_packets = summary["total_packets"]
    total_bytes = summary["total_bytes"]
    pps = packets_per_second(traffic)

    packet_columns = st.columns(4)
    packet_columns[0].metric("Total packets", f"{total_packets:,}")
    packet_columns[1].metric("Total traffic", format_bytes(total_bytes))
    packet_columns[2].metric("Packets/sec", f"{pps:.2f}")
    packet_columns[3].metric(
        "Database",
        "Connected",
        delta=f"{len(packets)} recent packets",
    )

    st.subheader("Traffic over time")
    if traffic:
        st.line_chart(
            {
                row["time_bucket"]: row["packet_count"]
                for row in traffic
            },
            y_label="Packets",
        )
    else:
        st.info("No traffic has been captured yet.")

    chart_columns = st.columns(2)

    with chart_columns[0]:
        st.subheader("Most common protocols")
        if protocols:
            st.bar_chart(
                {
                    row["protocol"]: row["packet_count"]
                    for row in protocols
                },
                y_label="Packets",
            )
        else:
            st.info("No protocol data available.")

    with chart_columns[1]:
        st.subheader("Top source MAC addresses")
        if source_macs:
            st.dataframe(
                source_macs,
                column_config={
                    "source_mac": "Source MAC",
                    "packet_count": "Packets",
                    "byte_count": st.column_config.NumberColumn(
                        "Traffic",
                        format="%.0f bytes",
                    ),
                },
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No source MAC data available.")

    st.subheader("Recent packets")
    if packets:
        st.dataframe(
            _display_packet_columns(packets),
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("No packets have been captured yet.")

    lower_columns = st.columns(2)

    with lower_columns[0]:
        st.subheader("All DNS domains")
        if dns_domains:
            st.dataframe(
                dns_domains,
                column_config={
                    "domain": "Domain",
                    "query_count": "Queries",
                },
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No DNS queries have been captured yet.")

    with lower_columns[1]:
        st.subheader("Alerts")
        if alerts:
            st.dataframe(
                alerts,
                column_config={
                    "created_at": "Created",
                    "alert_type": "Type",
                    "severity": "Severity",
                    "message": "Message",
                    "source_mac": "Source MAC",
                    "source_ip": "Source IP",
                    "packet_id": "Packet ID",
                },
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.success("No alerts have been recorded.")


def main() -> None:
    """Configure and run the Streamlit dashboard."""
    st.set_page_config(
        page_title="Packet Sniffer Dashboard",
        page_icon="📡",
        layout="wide",
    )

    st.title("Packet Sniffer Dashboard")
    st.caption("Live traffic view backed by SQLite")

    with st.sidebar:
        st.header("Settings")
        database_path_text = st.text_input(
            "Database path",
            value=str(database.DEFAULT_DATABASE_PATH),
        )
        packet_limit = st.number_input(
            "Recent packets",
            min_value=10,
            max_value=1000,
            value=DEFAULT_PACKET_LIMIT,
            step=10,
        )
        st.caption(f"Refreshes every {REFRESH_INTERVAL}.")

    selected_database_path = Path(database_path_text).expanduser()
    database.initialize_database(selected_database_path)

    _render_dashboard(selected_database_path, int(packet_limit))


if __name__ == "__main__":
    main()
