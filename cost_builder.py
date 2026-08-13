import os
import sqlite3
from pathlib import Path
from typing import Dict

try:
    import streamlit as st
except ImportError:  # pragma: no cover - chạy ở môi trường không có Streamlit
    st = None


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = str(BASE_DIR / "cost_matrix.db")
DEFAULT_SQL_PATH = str(BASE_DIR / "database.sql")


if st is None:
    def _cache_decorator(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
else:
    _cache_decorator = st.cache_data


def _initialize_database(db_path: str) -> None:
    if os.path.exists(db_path):
        return
    if not os.path.exists(DEFAULT_SQL_PATH):
        return
    connection = sqlite3.connect(db_path)
    try:
        with open(DEFAULT_SQL_PATH, "r", encoding="utf-8") as handle:
            connection.executescript(handle.read())
        connection.commit()
    finally:
        connection.close()


def get_db_version(db_path: str = DEFAULT_DB_PATH) -> str:
    _initialize_database(db_path)
    connection = sqlite3.connect(db_path)
    try:
        row = connection.execute("SELECT value FROM metadata WHERE key = 'db_version'").fetchone()
        return row[0] if row else "0"
    finally:
        connection.close()


@_cache_decorator(show_spinner=False)
def build_cost_dictionary(db_path: str = DEFAULT_DB_PATH, db_version: str | None = None) -> Dict[str, float]:
    """Tạo từ điển {privilege_name: final_cost} từ SQLite."""
    db_path = os.path.abspath(db_path)
    _initialize_database(db_path)
    if db_version is None:
        db_version = get_db_version(db_path)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        cursor = connection.execute(
            """
            SELECT
                p.privilege_name,
                td.fidelity_score,
                el.audit_score,
                el.sensor_score
            FROM privilege p
            JOIN privilege_technique pt ON p.id = pt.privilege_id
            JOIN technique_detection td ON pt.technique_id = td.technique_id
            JOIN event_log el ON td.event_id = el.event_id
            """
        )
        rows = cursor.fetchall()
    finally:
        connection.close()

    costs: Dict[str, float] = {}
    for row in rows:
        privilege_name = row["privilege_name"]
        technique_cost = float(row["fidelity_score"]) * float(row["audit_score"]) * float(row["sensor_score"])
        if privilege_name not in costs or technique_cost < costs[privilege_name]:
            costs[privilege_name] = technique_cost

    return costs


def load_cost_dictionary(db_path: str = DEFAULT_DB_PATH) -> Dict[str, float]:
    """Wrapper dùng để buộc cache được tính lại khi db_version thay đổi."""
    db_version = get_db_version(db_path)
    return build_cost_dictionary(db_path=db_path, db_version=db_version)


if __name__ == "__main__":
    print(load_cost_dictionary())
