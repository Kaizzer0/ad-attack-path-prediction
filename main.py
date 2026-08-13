import os
import re
import html
import shutil
import logging
import sqlite3
import importlib
from typing import Any, Dict, List
import json
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("ad_stealthiest_path")

try:
    import streamlit as st  # type: ignore
except ImportError:  # pragma: no cover
    st = None

try:
    from neo4j import GraphDatabase  # type: ignore
except ImportError:  # pragma: no cover
    GraphDatabase = None

try:
    import pyvis.network as net  # type: ignore
except ImportError:
    net = None

try:
    import streamlit.components.v1 as components  # type: ignore
except ImportError:
    components = None

from cost_builder import load_cost_dictionary
from graph_enricher import enrich_edges_with_cost
from data_cleaner import VALID_EDGE_TYPES

# Danh sách hiển thị trên dropdown "Relationship Type": sắp xếp theo bảng chữ cái cho dễ
# tìm, "MemberOf" đưa lên đầu làm mặc định vì đây là loại cạnh phổ biến nhất (lồng nhóm).
EDGE_TYPE_OPTIONS = ["MemberOf"] + sorted(t for t in VALID_EDGE_TYPES if t != "MemberOf")


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
DEFAULT_NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
DEFAULT_NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")


# Neo4j không cho phép parameter hóa tên label hoặc loại quan hệ (giới hạn của Cypher),
# nên mọi giá trị được nối trực tiếp vào chuỗi Cypher BẮT BUỘC phải qua allowlist này trước.
# (Vá bug: Cypher Injection qua relationship_type / attribute_name)
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_identifier(value: str, kind: str = "Identifier") -> str:
    """Chỉ cho phép chữ cái, số, dấu gạch dưới, không cho phép ký tự đặc biệt của Cypher."""
    if not value or not _IDENTIFIER_PATTERN.match(value):
        raise ValueError(
            f"{kind} không hợp lệ: '{value}'. Chỉ chấp nhận chữ cái, số và dấu gạch dưới."
        )
    return value


def get_driver(uri: str | None = None, user: str | None = None, password: str | None = None):
    """Tạo hoặc tái sử dụng driver Neo4j.

    Vá bug: trước đây hàm này chỉ tạo driver một lần duy nhất rồi cache mãi mãi trong
    session_state, nên đổi URI/user/password trong form Connect không có tác dụng.
    Nay driver được tạo lại (và driver cũ được đóng đúng cách) mỗi khi thông tin kết nối
    thay đổi.
    """
    if not (st and GraphDatabase):
        raise RuntimeError("Streamlit và neo4j cần được cài đặt trước khi chạy ứng dụng")

    uri = uri or DEFAULT_NEO4J_URI
    user = user or DEFAULT_NEO4J_USER
    password = password or DEFAULT_NEO4J_PASSWORD
    connection_key = (uri, user, password)

    if st.session_state.get("neo4j_driver_key") != connection_key:
        old_driver = st.session_state.get("neo4j_driver")
        if old_driver is not None:
            try:
                old_driver.close()
            except Exception:
                logger.warning("Không đóng được driver Neo4j cũ, bỏ qua.")
        try:
            new_driver = GraphDatabase.driver(uri, auth=(user, password))
            new_driver.verify_connectivity()
            st.session_state.neo4j_driver = new_driver
            st.session_state.neo4j_driver_key = connection_key
            logger.info("Đã kết nối Neo4j tại %s với user %s", uri, user)
        except Exception as e:
            logger.error("Lỗi kết nối Neo4j tại %s: %s", uri, e)
            st.error(f"Lỗi kết nối Neo4j: {e}")
            st.session_state.pop("neo4j_driver", None)
            st.session_state.pop("neo4j_driver_key", None)
            return None
    return st.session_state.neo4j_driver


def create_node(tx, node_id: str, node_name: str, node_label: str = "User"):
    allowed_labels = {"User", "Computer", "Group", "OU", "GPO", "DomainController"}
    if node_label not in allowed_labels:
        raise ValueError(f"Unsupported label: {node_label}")
    query = f"CREATE (n:{node_label} {{id: $node_id, name: $node_name}}) RETURN n"
    return tx.run(query, node_id=node_id, node_name=node_name).single()


def create_edge(tx, source_id: str, target_id: str, relationship_type: str = "MemberOf"):
    relationship_type = _validate_identifier(relationship_type, "Relationship type")
    query = """
    MATCH (source {id: $source_id}), (target {id: $target_id})
    CREATE (source)-[r:%s]->(target) RETURN r
    """ % relationship_type
    return tx.run(query, source_id=source_id, target_id=target_id).single()


def update_node_name(tx, node_id: str, new_name: str):
    query = "MATCH (n {id: $node_id}) SET n.name = $new_name RETURN n"
    return tx.run(query, node_id=node_id, new_name=new_name).single()


def set_edge_techniques(tx, source_id: str, target_id: str, techniques_list: List[str], relationship_type: str = "MemberOf"):
    relationship_type = _validate_identifier(relationship_type, "Relationship type")
    query = """
    MATCH (source {id: $source_id})-[r:%s]->(target {id: $target_id})
    SET r.techniques = $techniques_list RETURN r
    """ % relationship_type
    return tx.run(query, source_id=source_id, target_id=target_id, techniques_list=techniques_list).single()


def remove_node_attribute(tx, node_id: str, attribute_name: str = "name"):
    attribute_name = _validate_identifier(attribute_name, "Attribute name")
    query = "MATCH (n {id: $node_id}) REMOVE n.%s RETURN n" % attribute_name
    return tx.run(query, node_id=node_id).single()


def delete_edge(tx, source_id: str, target_id: str, relationship_type: str = "MemberOf"):
    relationship_type = _validate_identifier(relationship_type, "Relationship type")
    query = """
    MATCH (source {id: $source_id})-[r:%s]->(target {id: $target_id}) DELETE r
    """ % relationship_type
    return tx.run(query, source_id=source_id, target_id=target_id).single()


def delete_node(tx, node_id: str):
    query = "MATCH (n {id: $node_id}) DETACH DELETE n"
    return tx.run(query, node_id=node_id).single()


def reset_graph(driver) -> None:
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")


def get_graph_preview(driver, limit: int = 300) -> Dict[str, Any]:
    with driver.session() as session:
        rows = session.run(
            "MATCH (n)-[r]->(m) RETURN {source: n.id, target: m.id, type: type(r), cost: r.cost} as edge, {id: n.id, name: n.name, label: labels(n)[0]} as source_node, {id: m.id, name: m.name, label: labels(m)[0]} as target_node LIMIT $limit",
            limit=limit,
        )
        edges = [record.data() for record in rows]

        # Vá bug: "MATCH (n)-[r]->(m)" chỉ trả về node đã có ít nhất 1 cạnh, nên node
        # vừa tạo bằng "Manage Nodes > Create" (chưa nối cạnh nào) hoặc node bị mồ côi
        # sau khi "Manage Edges > Delete" xóa cạnh cuối cùng của nó sẽ không bao giờ
        # xuất hiện trên đồ thị dù đã lưu đúng trong Neo4j. Truy vấn thêm các node
        # không có quan hệ nào để hiển thị đầy đủ.
        isolated_rows = session.run(
            "MATCH (n) WHERE NOT (n)--() RETURN {id: n.id, name: n.name, label: labels(n)[0]} as node LIMIT $limit",
            limit=limit,
        )
        isolated_nodes = [record.data()["node"] for record in isolated_rows]

        return {"edges": edges, "isolated_nodes": isolated_nodes}


def get_shortest_path_details(driver, node_ids: List[str]) -> List[Dict[str, Any]]:
    """Truy vấn chính xác các mối quan hệ dọc theo đường đi Dijkstra để gộp dữ liệu."""
    if not node_ids or len(node_ids) < 2:
        return []
    
    results = []
    with driver.session() as session:
        for idx in range(len(node_ids) - 1):
            source_id = node_ids[idx]
            target_id = node_ids[idx + 1]
            rows = session.run("""
                MATCH (n {id: $source_id})-[r]-(m {id: $target_id})
                RETURN {source: startNode(r).id, target: endNode(r).id, type: type(r), cost: r.cost} as edge,
                       {id: startNode(r).id, name: startNode(r).name, label: labels(startNode(r))[0]} as source_node,
                       {id: endNode(r).id, name: endNode(r).name, label: labels(endNode(r))[0]} as target_node
                LIMIT 1
            """, source_id=source_id, target_id=target_id)
            
            record = rows.single()
            if record:
                results.append(record.data())
    return results


def render_find_path_result_dialog() -> None:
    """Hiển thị kết quả Find Path trong Dialog/Modal để tránh chiếm sidebar."""
    result = st.session_state.get("find_path_dialog_result")
    if not result:
        return

    @st.dialog("Find Path Result")
    def _dialog() -> None:
        status = result.get("status")
        title = result.get("title", "Kết quả Find Path")
        message = result.get("message", "")
        details = result.get("details", [])

        st.subheader(title)
        if status == "success":
            st.success(message)
        elif status == "warning":
            st.warning(message)
        else:
            st.error(message)

        for line in details:
            st.write(line)

        st.divider()
        if st.button("Đóng", type="primary", key="close_find_path_dialog"):
            st.session_state.find_path_dialog_open = False
            st.session_state.find_path_dialog_result = None
            st.rerun()

    _dialog()


def visualize_graph_with_pyvis(
    edges_data: List[Dict],
    highlighted_path: List[str] | None = None,
    isolated_nodes: List[Dict] | None = None,
) -> str | None:
    """Tạo HTML biểu đồ tương tác tĩnh, màu chuẩn Neo4j, có khoảng cách giãn rộng và Legend."""
    if not net:
        return None
    
    g = net.Network(height="700px", width="100%", directed=True, notebook=False, cdn_resources="remote")
    
    # 1. Bảng màu chuẩn Neo4j
    neo4j_colors = {
        "User": "#4C8EDA",
        "Computer": "#57C7E3",
        "DomainController": "#8DCC93",
        "Group": "#F16667",
        "OU": "#FFC454",
        "GPO": "#D9C8AE",
    }
    default_color = "#A5ABB6"

    nodes_set = set()
    edge_list = []
    
    for edge_data in edges_data:
        edge = edge_data.get("edge", {})
        source_node = edge_data.get("source_node", {})
        target_node = edge_data.get("target_node", {})
        
        source_id = source_node.get("id")
        target_id = target_node.get("id")
        
        if source_id and target_id:
            # Dữ liệu tên node đến từ đối tượng AD thực (SharpHound), không đáng tin cậy,
            # phải escape HTML trước khi render vào tooltip/label (vá bug: XSS)
            nodes_set.add((source_id, source_node.get("name") or source_id, source_node.get("label", "User")))
            nodes_set.add((target_id, target_node.get("name") or target_id, target_node.get("label", "User")))
            edge_list.append((source_id, target_id, edge.get("type", ""), edge.get("cost")))

    # Vá bug: node vừa Create hoặc bị mồ côi sau khi Delete Edge không có cạnh nào,
    # nên phải thêm riêng vào nodes_set (không đi qua edges_data ở trên) thì mới hiển thị.
    for node in (isolated_nodes or []):
        node_id = node.get("id")
        if node_id:
            nodes_set.add((node_id, node.get("name") or node_id, node.get("label", "User")))

    # Đưa các cặp cạnh trên đường đi vào tập hợp để highlight (chấp nhận cả 2 chiều để tránh lỗi hướng quan hệ)
    highlighted_edges = set()
    if highlighted_path and len(highlighted_path) > 1:
        for idx in range(len(highlighted_path) - 1):
            u = highlighted_path[idx]
            v = highlighted_path[idx + 1]
            highlighted_edges.add((u, v))
            highlighted_edges.add((v, u))
    
    # 2. Thêm Nodes
    for node_id, node_name, node_label in nodes_set:
        base_color = neo4j_colors.get(node_label, default_color)
        # Escape toàn bộ dữ liệu hiển thị vì đến từ đối tượng AD không đáng tin cậy (vá bug: XSS)
        safe_name = html.escape(str(node_name))
        safe_label = html.escape(str(node_label))
        safe_id = html.escape(str(node_id))

        # Nếu node nằm trong đường đi Dijkstra, đổi viền đỏ và đổi màu chữ thành đỏ nổi bật
        if highlighted_path and node_id in highlighted_path:
            node_color = {"background": base_color, "border": "#FF0000", "highlight": {"background": base_color, "border": "#FF0000"}}
            border_width = 4
            font_config = {"color": "#FF0000", "size": 14, "face": "arial", "strokeWidth": 2, "strokeColor": "#ffffff"}
        else:
            node_color = {"background": base_color, "border": "#2B7CE9"}
            border_width = 1
            font_config = {"color": "black", "size": 12, "face": "arial"}

        g.add_node(
            n_id=node_id, 
            label=safe_name, 
            title=f"Label: {safe_label}\nID: {safe_id}",
            color=node_color,
            borderWidth=border_width,
            shape="dot",
            size=25,
            font=font_config
        )
    
    # 3. Thêm Edges
    for source, target, edge_type, cost in edge_list:
        is_highlighted = (source, target) in highlighted_edges
        edge_color = "#FF0000" if is_highlighted else "#A5ABB6"
        edge_width = 4 if is_highlighted else 1

        safe_edge_type = html.escape(str(edge_type))
        label = f"{safe_edge_type}" + (f" ({cost})" if cost else "")
        custom_edge_id = f"EDGE: {html.escape(str(source))} -[{safe_edge_type}]-> {html.escape(str(target))}"
        
        g.add_edge(
            source, target, 
            id=custom_edge_id,
            label=label, 
            color=edge_color, 
            width=edge_width,
            title=f"Type: {safe_edge_type}\nCost: {html.escape(str(cost))}"
        )
    
    # 4. Cấu hình Physics: Khoảng cách giãn rộng gấp 3 lần
    g.set_options("""
    var options = {
      "physics": {
        "stabilization": {
          "enabled": true,
          "iterations": 1000,
          "fit": true
        },
        "barnesHut": {
          "gravitationalConstant": -80000, 
          "centralGravity": 0.1,
          "springLength": 300, 
          "springConstant": 0.01
        }
      },
      "interaction": {
        "hover": true,
        "navigationButtons": true
      },
      "edges": {
        "smooth": {
          "type": "continuous",
          "forceDirection": "none"
        },
        "font": {"size": 12, "align": "middle", "color": "black"}
      }
    }
    """)
    
    html_content = g.generate_html()
    
    # 5. INJECT JAVASCRIPT & CSS (Click-to-copy, Đóng băng đồ thị, Bảng chú thích Legend)
    custom_js_css = """
    <style>
        /* CSS cho Snack-bar Copied */
        #snackbar {
            visibility: hidden; min-width: 250px; background-color: #333; 
            color: #fff; text-align: center; border-radius: 8px; padding: 16px; 
            position: fixed; z-index: 9999; left: 50%; bottom: 30px; 
            transform: translateX(-50%); font-family: sans-serif; box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        #snackbar.show { visibility: visible; animation: fadein 0.5s, fadeout 0.5s 2.5s; }
        @keyframes fadein { from {bottom: 0; opacity: 0;} to {bottom: 30px; opacity: 1;} }
        @keyframes fadeout { from {bottom: 30px; opacity: 1;} to {bottom: 0; opacity: 0;} }
        
        /* CSS cho Bảng chú thích Legend */
        #graph-legend {
            position: absolute;
            top: 15px;
            right: 15px;
            background-color: rgba(255, 255, 255, 0.95);
            border: 1px solid #ccc;
            border-radius: 8px;
            padding: 15px;
            font-family: sans-serif;
            font-size: 14px;
            z-index: 999;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .legend-item { display: flex; align-items: center; margin-bottom: 8px; }
        .legend-color { width: 16px; height: 16px; border-radius: 50%; margin-right: 10px; border: 1px solid #999; }
    </style>
    
    <!-- Legend UI -->
    <div id="graph-legend">
        <div style="font-weight: bold; margin-bottom: 12px; border-bottom: 1px solid #eee; padding-bottom: 5px;">Node Legend</div>
        <div class="legend-item"><div class="legend-color" style="background-color: #4C8EDA;"></div>User</div>
        <div class="legend-item"><div class="legend-color" style="background-color: #57C7E3;"></div>Computer</div>
        <div class="legend-item"><div class="legend-color" style="background-color: #8DCC93;"></div>DomainController</div>
        <div class="legend-item"><div class="legend-color" style="background-color: #F16667;"></div>Group</div>
        <div class="legend-item"><div class="legend-color" style="background-color: #FFC454;"></div>OU</div>
        <div class="legend-item"><div class="legend-color" style="background-color: #D9C8AE;"></div>GPO</div>
    </div>

    <!-- Snackbar UI -->
    <div id="snackbar">Copied to clipboard!</div>
    
    <script type="text/javascript">
        function fallbackCopyTextToClipboard(text) {
            var textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.top = "0"; textArea.style.left = "0"; textArea.style.position = "fixed";
            document.body.appendChild(textArea);
            textArea.focus(); textArea.select();
            try { document.execCommand('copy'); } catch (err) {}
            document.body.removeChild(textArea);
        }

        setTimeout(function() {
            if (typeof network !== 'undefined') {
                
                // ĐÓNG BĂNG ĐỒ THỊ: Dừng lại sau khi sắp xếp xong (Kéo 1 node không làm chạy cả đồ thị)
                network.on("stabilizationIterationsDone", function () {
                    network.setOptions( { physics: false } );
                });

                // SỰ KIỆN CLICK COPY
                network.on("click", function (params) {
                    var textToCopy = "";
                    
                    if (params.nodes.length > 0) {
                        textToCopy = params.nodes[0];
                    } else if (params.edges.length > 0) {
                        textToCopy = params.edges[0];
                    }

                    if (textToCopy !== "") {
                        if (!navigator.clipboard) { fallbackCopyTextToClipboard(textToCopy); } 
                        else { navigator.clipboard.writeText(textToCopy); }
                        
                        var snackbar = document.getElementById("snackbar");
                        snackbar.innerHTML = "<b>Copied!</b><br><span style='font-size: 12px'>" + textToCopy + "</span>";
                        snackbar.className = "show";
                        setTimeout(function(){ snackbar.className = snackbar.className.replace("show", ""); }, 3000);
                    }
                });
            }
        }, 1500);
    </script>
    """
    
    html_content = html_content.replace('</body>', custom_js_css + '</body>')
    return html_content


@st.cache_data(show_spinner=False)
def get_dijkstra_relationship_types(db_path: str) -> str:
    """Sinh chuỗi loại cạnh cho apoc.algo.dijkstra động từ bảng privilege trong SQLite.

    Vá bug: trước đây danh sách này bị hard code chỉ 14/44 loại cạnh hợp lệ, khiến
    Dijkstra bỏ sót nhiều đường tấn công thật (ví dụ AddKeyCredentialLink).
    Đồng thời bổ sung các loại cạnh cấu trúc (MemberOf, Contains, GPLink, DCFor) không
    nằm trong bảng privilege nhưng vẫn hợp lệ trong đồ thị.
    """
    structural_edge_types = ["MemberOf", "Contains", "GPLink", "DCFor"]
    try:
        conn = sqlite3.connect(db_path)
        rows = conn.execute("SELECT privilege_name FROM privilege").fetchall()
        conn.close()
        privilege_types = [row[0] for row in rows]
    except Exception:
        logger.exception("Không đọc được bảng privilege từ %s, dùng danh sách rút gọn.", db_path)
        privilege_types = []

    all_types = sorted(set(structural_edge_types) | set(privilege_types))
    # Thêm dấu '>' vào sau mỗi loại cạnh để ép thuật toán tìm đường một chiều (outgoing)
    return "|".join([f"{edge_type}>" for edge_type in all_types])


def dijkstra_shortest_path(driver, source_id: str, target_id: str) -> tuple[List[str], float | None]:
    """Trả về (danh sách node ID trên đường đi, tổng chi phí phát hiện).

    Vá bug: trước đây câu Cypher chỉ "YIELD path", bỏ qua cột "weight" mà
    apoc.algo.dijkstra đã tính sẵn (tổng trọng số "cost" dọc đường đi ngắn nhất),
    khiến tổng chi phí phát hiện của đường tấn công không bao giờ tới được giao diện
    dù bản thân thuật toán đã tính ra con số này.
    """
    relationship_types = get_dijkstra_relationship_types(os.path.join(BASE_DIR, "cost_matrix.db"))
    with driver.session() as session:
        result = session.run("""
            MATCH (source {id: $source_id}), (target {id: $target_id})
            CALL apoc.algo.dijkstra(source, target, $relationship_types, "cost")
            YIELD path, weight
            RETURN [node in nodes(path) | node.id] as node_ids, weight
        """, source_id=source_id, target_id=target_id, relationship_types=relationship_types)

        record = result.single()
        if record:
            logger.info(
                "Dijkstra %s -> %s: %d node trên đường đi, tổng cost=%s",
                source_id, target_id, len(record["node_ids"]), record["weight"],
            )
            return record["node_ids"], record["weight"]
        logger.info("Dijkstra %s -> %s: không tìm thấy đường đi", source_id, target_id)
        return [], None


def run_data_cleansing_pipeline(uploaded_files: List[Any]) -> bool:
    """Lưu trữ tệp tin tải lên, thực thi module data_cleaner và di chuyển kết quả vào thư mục import."""
    try:
        # 1. Dọn dẹp các tệp JSON thô cũ trong BASE_DIR để tránh lỗi dính dữ liệu cũ
        for f_name in os.listdir(BASE_DIR):
            if f_name.endswith(".json") and f_name not in ["nodes_clean.json", "edges_clean.json"]:
                try:
                    os.remove(os.path.join(BASE_DIR, f_name))
                except Exception:
                    pass

        # 2. Ghi các file SharpHound JSON thô mới do người dùng vừa upload
        for uploaded_file in uploaded_files:
            file_path = os.path.join(BASE_DIR, uploaded_file.name)
            with open(file_path, "wb") as f_handle:
                f_handle.write(uploaded_file.getbuffer()) # <--- ĐÃ SỬA LỖI f thành f_handle (Đồng bộ tên biến)

        # 3. Tạm thời chuyển Working Directory về BASE_DIR để tương thích với data_cleaner
        old_cwd = os.getcwd()
        os.chdir(BASE_DIR)

        # Import động module data_cleaner để chạy hàm main()
        import data_cleaner
        importlib.reload(data_cleaner)
        data_cleaner.main()
        logger.info("Đã chạy xong data_cleaner.main()")

        # 3b. Gán cost cho từng cạnh (Vá bug: bước này trước đây bị bỏ sót hoàn toàn,
        # khiến mọi cạnh nạp vào Neo4j có cost = null và Dijkstra không hoạt động đúng)
        enrich_edges_with_cost(
            edges_path=os.path.join(BASE_DIR, "edges_clean.json"),
            output_path=os.path.join(BASE_DIR, "edges_clean.json"),
            db_path=os.path.join(BASE_DIR, "cost_matrix.db"),
        )
        logger.info("Đã gán cost cho các cạnh (enrich_edges_with_cost)")

        # 4. Di chuyển hai tệp clean sinh ra vào ./shared_data/, đây là thư mục THỰC SỰ
        # được mount vào /var/lib/neo4j/import trong docker-compose.yml.
        # (Vá bug: trước đây file bị move vào ./import/, một thư mục KHÔNG được mount
        # vào container Neo4j, khiến apoc.load.json luôn báo lỗi không tìm thấy file)
        import_dir = os.path.join(BASE_DIR, "shared_data")
        os.makedirs(import_dir, exist_ok=True)

        if os.path.exists("nodes_clean.json"):
            shutil.move("nodes_clean.json", os.path.join(import_dir, "nodes_clean.json"))
        if os.path.exists("edges_clean.json"):
            shutil.move("edges_clean.json", os.path.join(import_dir, "edges_clean.json"))

        # 5. Dọn dẹp sạch sẽ các tệp SharpHound gốc đã upload để giải phóng không gian
        for uploaded_file in uploaded_files:
            try:
                os.remove(os.path.join(BASE_DIR, uploaded_file.name))
            except Exception:
                pass

        # Khôi phục lại thư mục làm việc gốc
        os.chdir(old_cwd)
        return True
    except Exception as error:
        logger.exception("Lỗi trong quá trình xử lý làm sạch dữ liệu")
        st.error(f"Lỗi trong quá trình xử lý làm sạch dữ liệu: {error}")
        return False


def import_graph_from_json(driver) -> Dict[str, Any]:
    # Vá bug: đường dẫn cũ "file:///import/nodes_clean.json" thừa một cấp "import/".
    # Với apoc.import.file.use_neo4j_config=true (apoc.conf), APOC diễn giải path này
    # tương đối so với thư mục import đã cấu hình, tức tìm sai vị trí
    # <neo4j_import_dir>/import/nodes_clean.json (không tồn tại). Đường dẫn đúng là
    # tương đối trực tiếp so với thư mục import (chính là ./shared_data đã mount).
    nodes_path = "file:///nodes_clean.json"
    edges_path = "file:///edges_clean.json"

    with driver.session() as session:
        nodes_result = session.run(f"""
            CALL apoc.load.json("{nodes_path}") YIELD value
            CALL apoc.merge.node([value.type], {{id: value.id}}, {{name: value.name}}, {{}}) YIELD node
            RETURN count(node) AS nodes_created
        """)

        edges_result = session.run(f"""
            CALL apoc.load.json("{edges_path}") YIELD value
            MATCH (source {{id: value.source}})
            MATCH (target {{id: value.target}})
            CALL apoc.merge.relationship(
                source, 
                value.type, 
                {{}}, 
                {{
                    techniques: coalesce(value.techniques, []), 
                    events: coalesce(value.events, []), 
                    filters: coalesce(value.filters, []), 
                    cost: coalesce(value.cost, null)
                }}, 
                target
            ) YIELD rel
            RETURN count(rel) AS edges_created
        """)

        nodes_summary = nodes_result.single()
        edges_summary = edges_result.single()
        logger.info(
            "Import Neo4j hoàn tất: %s nodes, %s edges",
            nodes_summary["nodes_created"] if nodes_summary else 0,
            edges_summary["edges_created"] if edges_summary else 0,
        )
        return {"nodes": nodes_summary, "edges": edges_summary}


def render_graph_preview(driver, highlighted_path: List[str] | None = None) -> None:
    if not (components and net):
        st.info("PyVis chưa sẵn sàng để trực quan hóa đồ thị.")
        return

    # Kiểm tra xem có đang ở chế độ Focus Path hay không
    focus_path = st.session_state.get("focus_path", False)
    
    isolated_nodes: List[Dict[str, Any]] = []

    if focus_path and highlighted_path and len(highlighted_path) > 1:
        # Chế độ Focus: Chỉ lấy đúng các node/edge thuộc đường đi Dijkstra
        # (không cần node cô lập ở đây vì Focus View chủ đích chỉ hiện đường đi)
        edges_data = get_shortest_path_details(driver, highlighted_path)
    else:
        # Chế độ thông thường: Lấy preview 3000 cạnh cùng các node chưa có cạnh nào
        preview_result = get_graph_preview(driver, limit=3000)
        preview_data = preview_result["edges"]
        isolated_nodes = preview_result["isolated_nodes"]

        if highlighted_path and len(highlighted_path) > 1:
            # Gộp dữ liệu đường đi Dijkstra vào dữ liệu preview để đảm bảo không bị thiếu node/edge nào
            path_data = get_shortest_path_details(driver, highlighted_path)
            seen_edges = set()
            edges_data = []
            
            # Ưu tiên thêm các cạnh thuộc đường đi ngắn nhất trước
            for item in path_data:
                edge = item.get("edge", {})
                edge_key = (edge.get("source"), edge.get("target"), edge.get("type"))
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    edges_data.append(item)
                    
            # Thêm các cạnh preview thông thường vào sau (nếu chưa tồn tại)
            for item in preview_data:
                edge = item.get("edge", {})
                edge_key = (edge.get("source"), edge.get("target"), edge.get("type"))
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    edges_data.append(item)
        else:
            edges_data = preview_data

    if not edges_data and not isolated_nodes:
        st.info("No graph data found. Import graph first.")
        return

    html_content = visualize_graph_with_pyvis(edges_data, highlighted_path, isolated_nodes)
    if html_content:
        components.html(html_content, height=730, scrolling=True)


def main() -> None:
    st.set_page_config(page_title="AD Stealthiest Attack Path", layout="wide")
    st.title("AD Stealthiest Attack Path")
    
    if "connected" not in st.session_state:
        st.session_state.connected = False
    if "highlighted_path" not in st.session_state:
        st.session_state.highlighted_path = []
    if "show_connection_dialog" not in st.session_state:
        st.session_state.show_connection_dialog = False
    if "show_cost_dict" not in st.session_state:
        st.session_state.show_cost_dict = False
    if "show_node_ops" not in st.session_state:
        st.session_state.show_node_ops = False
    if "show_edge_ops" not in st.session_state:
        st.session_state.show_edge_ops = False
    if "show_dijkstra" not in st.session_state:
        st.session_state.show_dijkstra = False
    if "find_path_dialog_open" not in st.session_state:
        st.session_state.find_path_dialog_open = False
    if "find_path_dialog_result" not in st.session_state:
        st.session_state.find_path_dialog_result = None
    if "show_import_dialog" not in st.session_state:
        st.session_state.show_import_dialog = False

    with st.sidebar:
        st.markdown("### Control Panel")
        if st.button("Connect to Neo4j"):
            st.session_state.show_connection_dialog = True

        if st.session_state.get("show_connection_dialog"):
            st.divider()
            st.markdown("#### Neo4j Connection")
            uri = st.text_input("Neo4j URI", value=DEFAULT_NEO4J_URI, key="uri_input")
            user = st.text_input("User", value=DEFAULT_NEO4J_USER, key="user_input")
            password = st.text_input("Password", value=DEFAULT_NEO4J_PASSWORD, type="password", key="pass_input")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("✓ Connect"):
                    driver = get_driver(uri, user, password)
                    if driver:
                        st.session_state.connected = True
                        st.session_state.show_connection_dialog = False
                        st.rerun()
            with col2:
                if st.button("✕ Cancel"):
                    st.session_state.show_connection_dialog = False
                    st.rerun()

        if st.session_state.connected:
            st.success("✓ Connected")

        st.divider()
        if st.button("View Cost Dictionary"):
            st.session_state.show_cost_dict = not st.session_state.get("show_cost_dict", False)

        if st.button("Reset Graph"):
            st.session_state.show_reset_confirm = True

        # Vá bug: trước đây nút Reset xóa toàn bộ đồ thị ngay lập tức, không có bước
        # xác nhận, chỉ cần bấm nhầm là mất hết dữ liệu đã import không thể hoàn tác.
        if st.session_state.get("show_reset_confirm"):
            st.warning("Hành động này sẽ XÓA TOÀN BỘ dữ liệu trong đồ thị và không thể hoàn tác.")
            confirm_text = st.text_input(
                "Gõ chính xác CONFIRM để xác nhận xóa", key="reset_confirm_input"
            )
            col_r1, col_r2 = st.columns(2)
            with col_r1:
                if st.button("✓ Xác nhận Reset", key="confirm_reset_btn", disabled=(confirm_text != "CONFIRM")):
                    driver = get_driver()
                    if driver:
                        try:
                            reset_graph(driver)
                            st.session_state.highlighted_path = []
                            st.session_state.show_reset_confirm = False
                            logger.warning("Người dùng đã reset toàn bộ đồ thị Neo4j")
                            st.success("Graph reset successfully!")
                            st.rerun()
                        except Exception as e:
                            logger.exception("Reset graph thất bại")
                            st.error(f"Reset failed: {e}")
            with col_r2:
                if st.button("✕ Hủy", key="cancel_reset_btn"):
                    st.session_state.show_reset_confirm = False
                    st.rerun()

        # Nút bấm kích hoạt form upload
        if st.button("Import Graph from JSON"):
            st.session_state.show_import_dialog = True
            st.rerun()

        st.divider()

        if st.button("Manage Nodes"):
            st.session_state.show_node_ops = not st.session_state.show_node_ops
        if st.session_state.show_node_ops:
            node_action = st.radio("Node Action", ["Create", "Update", "Delete", "Remove Attribute"], key="node_action")
            node_label = st.selectbox("Label", ["User", "Computer", "Group", "OU", "GPO", "DomainController"], key="node_label")
            node_id = st.text_input("Node ID", key="node_id_action")
            node_name = st.text_input("Node Name / New Name", key="node_name_action")
            if node_action == "Remove Attribute":
                attribute_name = st.text_input("Attribute Name", value="name", key="node_attr_action")
            if st.button("Apply Node Action", key="apply_node_action"):
                driver = get_driver()
                if driver and node_id:
                    try:
                        with driver.session() as session:
                            if node_action == "Create" and node_name:
                                session.execute_write(create_node, node_id, node_name, node_label)
                                st.session_state.highlighted_path = [node_id]
                            elif node_action == "Update" and node_name:
                                session.execute_write(update_node_name, node_id, node_name)
                                st.session_state.highlighted_path = [node_id]
                            elif node_action == "Delete":
                                session.execute_write(delete_node, node_id)
                                st.session_state.highlighted_path = []
                            elif node_action == "Remove Attribute":
                                session.execute_write(remove_node_attribute, node_id, attribute_name)
                                st.session_state.highlighted_path = [node_id]
                        logger.info("Node action '%s' trên node %s thành công", node_action, node_id)
                        st.success(f"Node action '{node_action}' completed!")
                    except Exception as e:
                        logger.exception("Node action '%s' trên node %s thất bại", node_action, node_id)
                        st.error(f"Node action failed: {e}")

        if st.button("Manage Edges"):
            st.session_state.show_edge_ops = not st.session_state.show_edge_ops

        if st.session_state.get("show_edge_ops"):
            edge_action = st.radio("Action", ["Create", "Update", "Delete"], key="edge_action")
            
            if edge_action == "Create":
                st.markdown("#### Create Edge")
                source_id = st.text_input("Source ID", key="edge_source_create")
                target_id = st.text_input("Target ID", key="edge_target_create")
                rel_type = st.selectbox("Relationship Type", options=EDGE_TYPE_OPTIONS, key="edge_type_create")
                if st.button("Create Edge", key="create_edge_btn"):
                    driver = get_driver()
                    if driver and source_id and target_id:
                        try:
                            with driver.session() as session:
                                session.execute_write(create_edge, source_id, target_id, rel_type)
                            st.session_state.highlighted_path = [source_id, target_id]
                            logger.info("Đã tạo cạnh %s -[%s]-> %s", source_id, rel_type, target_id)
                            st.success("Edge created!")
                        except Exception as e:
                            logger.exception("Tạo cạnh %s -[%s]-> %s thất bại", source_id, rel_type, target_id)
                            st.error(f"Create failed: {e}")
            
            elif edge_action == "Update":
                st.markdown("#### Update Edge Techniques")
                source_id = st.text_input("Source ID", key="edge_source_update")
                target_id = st.text_input("Target ID", key="edge_target_update")
                rel_type = st.selectbox("Relationship Type", options=EDGE_TYPE_OPTIONS, key="edge_type_update")
                techniques = st.text_area("Techniques (comma-separated)", key="edge_techniques")
                if st.button("Update Edge", key="update_edge_btn"):
                    driver = get_driver()
                    if driver and source_id and target_id and techniques:
                        try:
                            tech_list = [t.strip() for t in techniques.split(",")]
                            with driver.session() as session:
                                session.execute_write(set_edge_techniques, source_id, target_id, tech_list, rel_type)
                            st.session_state.highlighted_path = [source_id, target_id]
                            logger.info("Đã cập nhật techniques cho cạnh %s -[%s]-> %s", source_id, rel_type, target_id)
                            st.success("Edge updated!")
                        except Exception as e:
                            logger.exception("Cập nhật cạnh %s -[%s]-> %s thất bại", source_id, rel_type, target_id)
                            st.error(f"Update failed: {e}")
            
            elif edge_action == "Delete":
                st.markdown("#### Delete Edge")
                source_id = st.text_input("Source ID", key="edge_source_delete")
                target_id = st.text_input("Target ID", key="edge_target_delete")
                rel_type = st.selectbox("Relationship Type", options=EDGE_TYPE_OPTIONS, key="edge_type_delete")
                if st.button("Delete Edge", key="delete_edge_btn"):
                    driver = get_driver()
                    if driver and source_id and target_id:
                        try:
                            with driver.session() as session:
                                session.execute_write(delete_edge, source_id, target_id, rel_type)
                            logger.info("Đã xóa cạnh %s -[%s]-> %s", source_id, rel_type, target_id)
                            st.success("Edge deleted!")
                        except Exception as e:
                            logger.exception("Xóa cạnh %s -[%s]-> %s thất bại", source_id, rel_type, target_id)
                            st.error(f"Delete failed: {e}")
        
        st.divider()

        if st.button("Find Shortest Path"):
            st.session_state.show_dijkstra = not st.session_state.show_dijkstra
        
        if st.session_state.get("show_dijkstra"):
            st.markdown("#### Dijkstra Path Finding")
            source = st.text_input("Source Node ID", key="dijkstra_source")
            target = st.text_input("Target Node ID", key="dijkstra_target")
            
            # Checkbox Focus View
            st.checkbox("Ẩn các Node không liên quan (Focus View)", key="focus_path")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Find Path", type="primary", key="find_path_btn"):
                    driver = get_driver()
                    if driver and source and target:
                        try:
                            path, total_cost = dijkstra_shortest_path(driver, source, target)
                            if path:
                                st.session_state.highlighted_path = path
                                dialog_details = [
                                    f"Source Node ID: {source}",
                                    f"Target Node ID: {target}",
                                    f"Số node trên path: {len(path)}",
                                ]
                                if total_cost is not None:
                                    dialog_details.append(f"Tổng chi phí phát hiện (cost): {total_cost:.2f}")
                                st.session_state.find_path_dialog_result = {
                                    "status": "success",
                                    "title": "Tìm thấy đường đi",
                                    "message": "Đã tìm thấy đường đi ít bị phát hiện nhất.",
                                    "details": dialog_details,
                                }
                            else:
                                st.session_state.find_path_dialog_result = {
                                    "status": "warning",
                                    "title": "Không tìm thấy đường đi",
                                    "message": "Không có đường đi phù hợp giữa Source và Target hiện tại.",
                                    "details": [
                                        f"Source Node ID: {source}",
                                        f"Target Node ID: {target}",
                                    ],
                                }
                            st.session_state.find_path_dialog_open = True
                        except Exception as e:
                            st.session_state.find_path_dialog_result = {
                                "status": "error",
                                "title": "Lỗi khi tìm đường",
                                "message": f"Path finding failed: {e}",
                                "details": [
                                    "Vui lòng kiểm tra lại dữ liệu đầu vào và trạng thái kết nối Neo4j.",
                                ],
                            }
                            st.session_state.find_path_dialog_open = True
            
            with col2:
                def clear_path_action():
                    st.session_state.highlighted_path = []
                    st.session_state.focus_path = False

                st.button("Back (Clear)", key="clear_path_btn", on_click=clear_path_action)

    # Hiển thị giao diện Form Upload kéo thả file thô SharpHound ở vùng nội dung chính khi kích hoạt
    if st.session_state.get("find_path_dialog_open"):
        render_find_path_result_dialog()

    # Hiển thị giao diện Form Upload kéo thả file thô SharpHound ở vùng nội dung chính khi kích hoạt
    if st.session_state.get("show_import_dialog"):
        st.divider()
        st.info("### Import Graph từ SharpHound Raw JSONs")
        st.markdown(
            "Vui lòng tải lên tối đa 6 tệp tin `.json` kết quả từ SharpHound (ví dụ: `*_users.json`, `*_computers.json`...). "
        )
        
        uploaded_files = st.file_uploader(
            "Kéo thả các tệp SharpHound tại đây (Tối đa 6 tệp)", 
            type=["json"], 
            accept_multiple_files=True,
            key="sharphound_uploader"
        )
        
        col_imp1, col_imp2 = st.columns(2)
        with col_imp1:
            if st.button("Bắt đầu Import", type="primary", key="start_import_btn"):
                if not uploaded_files:
                    st.warning("Vui lòng tải lên ít nhất 1 tệp tin JSON.")
                elif len(uploaded_files) > 6:
                    st.error("Chỉ chấp nhận tối đa 6 tệp tin JSON thô!")
                else:
                    driver = get_driver()
                    if driver:
                        with st.spinner("Đang chạy pipeline làm sạch dữ liệu và nạp đồ thị vào Neo4j..."):
                            # 1. Chạy pipeline làm sạch dữ liệu
                            cleansing_success = run_data_cleansing_pipeline(uploaded_files)
                            if cleansing_success:
                                try:
                                    # 2. Đọc file sạch trong thư mục import và nạp vào Neo4j
                                    result = import_graph_from_json(driver)
                                    nodes_created = result["nodes"]["nodes_created"]
                                    edges_created = result["edges"]["edges_created"]
                                    st.success(
                                        f"Nạp đồ thị thành công! Đã tạo: {nodes_created} nodes, {edges_created} edges."
                                    )
                                    st.session_state.show_import_dialog = False
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Lỗi khi nạp dữ liệu vào cơ sở dữ liệu đồ thị Neo4j: {e}")
        with col_imp2:
            if st.button("✕ Hủy bỏ", key="cancel_import_btn"):
                st.session_state.show_import_dialog = False
                st.rerun()
    
    if st.session_state.get("show_cost_dict"):
        st.divider()
        st.subheader("Cost Dictionary")
        cost_dict = load_cost_dictionary(os.path.join(BASE_DIR, "cost_matrix.db"))
        cols = st.columns(3)
        for idx, (priv, cost) in enumerate(sorted(cost_dict.items())):
            with cols[idx % 3]:
                st.metric(priv, f"{cost:.1f}")
    
    st.divider()
    st.subheader("Graph Visualization")
    driver = get_driver()
    if driver and st.session_state.connected:
        try:
            render_graph_preview(driver, st.session_state.get("highlighted_path"))
        except Exception as e:
            st.warning(f"Visualization failed: {e}. Make sure Neo4j is connected and graph is loaded.")
    else:
        st.info("Connect to Neo4j first to view the graph.")


if __name__ == "__main__":
    main()