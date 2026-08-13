import json
import shutil
from pathlib import Path
from typing import Any, Dict

from cost_builder import load_cost_dictionary


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_NODES_PATH = BASE_DIR / "nodes_clean.json"
DEFAULT_EDGES_PATH = BASE_DIR / "edges_clean.json"
DEFAULT_SHARED_NODES_PATH = BASE_DIR / "shared_data" / "nodes_clean.json"
DEFAULT_SHARED_EDGES_PATH = BASE_DIR / "shared_data" / "edges_clean.json"
DEFAULT_DB_PATH = BASE_DIR / "cost_matrix.db"


def enrich_edges_with_cost(
    edges_path: str | Path | None = None,
    output_path: str | Path | None = None,
    db_path: str | Path | None = None,
) -> Dict[str, float]:
    """Đọc edges_clean.json, gán thuộc tính cost và ghi lại vào file import của Neo4j."""
    edges_path = Path(edges_path or DEFAULT_EDGES_PATH)
    output_path = Path(output_path or DEFAULT_SHARED_EDGES_PATH)
    db_path = Path(db_path or DEFAULT_DB_PATH)

    if not edges_path.exists():
        raise FileNotFoundError(f"Không tìm thấy file cạnh: {edges_path}")

    with edges_path.open("r", encoding="utf-8") as handle:
        edges = json.load(handle)

    cost_dictionary = load_cost_dictionary(str(db_path))

    enriched_edges: list[dict[str, Any]] = []
    for edge in edges:
        enriched_edge = dict(edge)
        privilege_name = edge.get("type")
        enriched_edge["cost"] = cost_dictionary.get(privilege_name)
        enriched_edges.append(enriched_edge)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(enriched_edges, handle, indent=2)

    if DEFAULT_NODES_PATH.exists():
        DEFAULT_SHARED_NODES_PATH.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(DEFAULT_NODES_PATH, DEFAULT_SHARED_NODES_PATH)

    # Đồng bộ lại file gốc để tiện dùng trong quá trình phát triển.
    if output_path.resolve() != edges_path.resolve():
        with edges_path.open("w", encoding="utf-8") as handle:
            json.dump(enriched_edges, handle, indent=2)

    return cost_dictionary


if __name__ == "__main__":
    enrich_edges_with_cost()
