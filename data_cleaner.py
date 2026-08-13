import json
import os
import sys
import logging
import sqlite3

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def load_json(file_path: str) -> dict:
    try:
        with open(file_path, "r", encoding="utf-8") as file_handle:
            return json.load(file_handle)
    except Exception as error:
        logging.error(f"Lỗi đọc file {file_path}: {error}")
        return {}

def save_json(data: list, file_path: str) -> None:
    with open(file_path, "w", encoding="utf-8") as file_handle:
        json.dump(data, file_handle, indent=2)

def is_valid_node(node_type: str) -> bool:
    valid_types = ["User", "Computer", "Group", "OU", "GPO", "DomainController"]
    return node_type in valid_types

# Danh sách 45 loại cạnh hợp lệ theo schema thật của dự án (SQL/BloodHound whitelist).
# Đây là NGUỒN DỮ LIỆU THẬT DUY NHẤT (single source of truth): data_cleaner.py dùng để
# lọc dữ liệu SharpHound thô, và main.py import lại chính hằng số này để build dropdown
# "Relationship Type" trong Manage Edges, đảm bảo người dùng chỉ được CHỌN trong đúng tập
# loại cạnh mà pipeline làm sạch dữ liệu công nhận là hợp lệ, không được tự gõ tay/thêm
# loại cạnh không tồn tại trong dữ liệu thật.
VALID_EDGE_TYPES = (
    "ForceChangePassword", "CanRDP", "AddMember", "GenericAll",
    "AllowedToAct", "HasSIDHistory", "GenericWrite", "WriteDacl",
    "WriteOwner", "WriteSPN", "ReadLAPSPassword", "ReadGMSAPassword",
    "CanPSRemote", "ExecuteDCOM", "AddSelf", "WriteAccountRestrictions",
    "AddAllowedToAct", "AllowedToDelegate", "AbuseTGTDelegation",
    "SpoofSIDHistory", "DumpSMSAPassword", "AdminTo", "AllExtendedRights",
    "Owns", "SQLAdmin", "AddKeyCredentialLink", "WriteGPLink",
    "RemoteInteractiveLogonRight", "HasSession", "DCSync", "DCFor",
    "CoerceToTGT", "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC6a",
    "ADCSESC6b", "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b",
    "ADCSESC13", "MemberOf", "Contains", "GPLink"
)


def is_valid_edge(edge_name: str) -> bool:
    return edge_name in VALID_EDGE_TYPES

def get_node_type(file_name: str) -> str:
    name = file_name.lower()
    if "users" in name: return "User"
    if "computers" in name: return "Computer"
    if "groups" in name: return "Group"
    if "ous" in name: return "OU"
    if "gpos" in name: return "GPO"
    if "domains" in name: return "Domain"
    return "Unknown"

def load_sqlite_enrichment(db_path: str) -> dict:
    enrichment = {}
    if not os.path.exists(db_path):
        logging.warning(f"Không tìm thấy file {db_path}.")
        return enrichment

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = """
            SELECT 
                p.privilege_name,
                pt.technique_id,
                td.event_id,
                td.filter_id
            FROM privilege p
            JOIN privilege_technique pt ON p.id = pt.privilege_id
            LEFT JOIN technique_detection td ON pt.technique_id = td.technique_id;
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            priv = row["privilege_name"]
            tech = row["technique_id"]
            event = row["event_id"]
            filt = row["filter_id"]

            if priv not in enrichment:
                enrichment[priv] = {
                    "techniques": set(),
                    "events": set(),
                    "filters": set()
                }

            if tech: enrichment[priv]["techniques"].add(tech)
            if event: enrichment[priv]["events"].add(event)
            if filt: enrichment[priv]["filters"].add(filt)

        for priv in enrichment:
            enrichment[priv]["techniques"] = list(enrichment[priv]["techniques"])
            enrichment[priv]["events"] = list(enrichment[priv]["events"])
            enrichment[priv]["filters"] = list(enrichment[priv]["filters"])

        logging.info("Trích xuất SQLite hoàn tất.")
        return enrichment
    except Exception as error:
        logging.error(f"Lỗi truy vấn SQLite: {error}")
        return {}

def validate_graph(nodes: list, edges: list) -> None:
    node_ids = {node["id"] for node in nodes}
    for node in nodes:
        if not is_valid_node(node["type"]):
            logging.error(f"Node sai định dạng: {node['id']} - {node['type']}")
            sys.exit(1)
    for edge in edges:
        if not is_valid_edge(edge["type"]):
            logging.error(f"Cạnh sai định dạng: {edge['type']}")
            sys.exit(1)
        if edge["source"] not in node_ids:
            logging.error(f"Nguồn không tồn tại: {edge['source']}")
            sys.exit(1)
        if edge["target"] not in node_ids:
            logging.error(f"Đích không tồn tại: {edge['target']}")
            sys.exit(1)
    logging.info("Dữ liệu đồ thị hợp lệ.")

def parse_edges(item: dict, node_id: str, raw_edges: list):
    pg = item.get("PrimaryGroupSID")
    if pg:
        raw_edges.append({"source": node_id, "target": pg, "type": "MemberOf"})
        
    for ace in item.get("Aces", []):
        right = ace.get("RightName")
        if is_valid_edge(right):
            raw_edges.append({"source": ace.get("PrincipalSID"), "target": node_id, "type": right})
            
    for member in item.get("Members", []):
        raw_edges.append({"source": member.get("ObjectIdentifier"), "target": node_id, "type": "MemberOf"})
        
    for child in item.get("ChildObjects", []):
        raw_edges.append({"source": node_id, "target": child.get("ObjectIdentifier"), "type": "Contains"})
        
    for link in item.get("Links", []):
        if "GUID" in link:
            raw_edges.append({"source": link.get("GUID"), "target": node_id, "type": "GPLink"})
            
    for session_type in ["Sessions", "PrivilegedSessions", "RegistrySessions"]:
        for session in item.get(session_type, {}).get("Results", []):
            user = session.get("UserSID")
            comp = session.get("ComputerSID")
            if user and comp:
                raw_edges.append({"source": user, "target": comp, "type": "HasSession"})
                
    for lg in item.get("LocalGroups", []):
        obj_id = str(lg.get("ObjectIdentifier", "")).upper()
        name = str(lg.get("Name", "")).upper()
        edge_type = None
        if "-544" in obj_id or "ADMINISTRATORS" in name: edge_type = "AdminTo"
        elif "-555" in obj_id or "REMOTE DESKTOP" in name: edge_type = "CanRDP"
        elif "-562" in obj_id or "DISTRIBUTED COM" in name: edge_type = "ExecuteDCOM"
        elif "-580" in obj_id or "REMOTE MANAGEMENT" in name: edge_type = "CanPSRemote"
        
        if edge_type:
            for res in lg.get("Results", []):
                raw_edges.append({"source": res.get("ObjectIdentifier"), "target": node_id, "type": edge_type})
                
    for ur in item.get("UserRights", []):
        if ur.get("Privilege") == "SeRemoteInteractiveLogonRight":
            for res in ur.get("Results", []):
                raw_edges.append({"source": res.get("ObjectIdentifier"), "target": node_id, "type": "RemoteInteractiveLogonRight"})
                
    for act in item.get("AllowedToAct", []):
        if isinstance(act, dict) and "ObjectIdentifier" in act:
            raw_edges.append({"source": act.get("ObjectIdentifier"), "target": node_id, "type": "AllowedToAct"})
            
    for dele in item.get("AllowedToDelegate", []):
        if isinstance(dele, dict) and "ObjectIdentifier" in dele:
            raw_edges.append({"source": node_id, "target": dele.get("ObjectIdentifier"), "type": "AllowedToDelegate"})
            
    for h in item.get("HasSIDHistory", []):
        if isinstance(h, dict) and "ObjectIdentifier" in h:
            raw_edges.append({"source": node_id, "target": h.get("ObjectIdentifier"), "type": "HasSIDHistory"})
            
    for dump in item.get("DumpSMSAPassword", []):
        if isinstance(dump, dict) and "ObjectIdentifier" in dump:
            raw_edges.append({"source": node_id, "target": dump.get("ObjectIdentifier"), "type": "DumpSMSAPassword"})

def main():
    nodes = []
    raw_edges = []
    domain_controllers = []
    domain_sids = []
    current_dir = "."

    sql_enrichment = load_sqlite_enrichment(os.path.join(current_dir, "cost_matrix.db"))

    for file_name in os.listdir(current_dir):
        if not file_name.endswith(".json"): continue
        
        if "computers" in file_name.lower():
            data = load_json(file_name)
            for item in data.get("data", []):
                props = item.get("Properties", {})
                if props.get("isdc") is True or item.get("IsDC") is True:
                    domain_controllers.append(item.get("ObjectIdentifier"))
                    
        if "domains" in file_name.lower():
            data = load_json(file_name)
            for item in data.get("data", []):
                domain_sids.append(item.get("ObjectIdentifier"))

    for file_name in os.listdir(current_dir):
        if not file_name.endswith(".json"): continue
        if file_name in ["nodes_clean.json", "edges_clean.json"]: continue
            
        node_type = get_node_type(file_name)
        data = load_json(file_name)
        
        for item in data.get("data", []):
            node_id = item.get("ObjectIdentifier")
            current_type = node_type
            
            if current_type == "Computer" and node_id in domain_controllers:
                current_type = "DomainController"
                
            if is_valid_node(current_type):
                nodes.append({
                    "id": node_id,
                    "type": current_type,
                    "name": item.get("Properties", {}).get("name")
                })
            
            parse_edges(item, node_id, raw_edges)

    node_ids = {node["id"] for node in nodes}
    final_edges = []
    seen = set()
    
    for edge in raw_edges:
        edge_type = edge.get("type")
        src_raw = edge.get("source")
        tgt_raw = edge.get("target")
        
        sources = domain_controllers if src_raw in domain_sids else [src_raw]
        targets = domain_controllers if tgt_raw in domain_sids else [tgt_raw]

        for src in sources:
            for tgt in targets:
                if src not in node_ids or tgt not in node_ids:
                    continue

                edge_hash = f"{src}-{edge_type}-{tgt}"
                if edge_hash in seen:
                    continue
                seen.add(edge_hash)

                clean_edge = {
                    "source": src,
                    "target": tgt,
                    "type": edge_type
                }

                if edge_type in sql_enrichment:
                    clean_edge["techniques"] = sql_enrichment[edge_type]["techniques"]
                    clean_edge["events"] = sql_enrichment[edge_type]["events"]
                    clean_edge["filters"] = sql_enrichment[edge_type]["filters"]

                final_edges.append(clean_edge)

    validate_graph(nodes, final_edges)

    save_json(nodes, "nodes_clean.json")
    save_json(final_edges, "edges_clean.json")
    logging.info("Hoàn tất pipeline.")

if __name__ == "__main__":
    main()