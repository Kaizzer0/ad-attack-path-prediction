// 1. TẠO CONSTRAINT 
CREATE CONSTRAINT unique_user_id IF NOT EXISTS FOR (n:User) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT unique_computer_id IF NOT EXISTS FOR (n:Computer) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT unique_group_id IF NOT EXISTS FOR (n:Group) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT unique_ou_id IF NOT EXISTS FOR (n:OU) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT unique_gpo_id IF NOT EXISTS FOR (n:GPO) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT unique_dc_id IF NOT EXISTS FOR (n:DomainController) REQUIRE n.id IS UNIQUE;

// 2. TẠO INDEX
CREATE INDEX node_name_index IF NOT EXISTS FOR (n:User) ON (n.name);

// 3. IMPORT DỮ LIỆU
CALL apoc.cypher.runMany('
    // Nhập Node
    CALL apoc.load.json("file:///nodes_clean.json") YIELD value
    CALL apoc.merge.node([value.type], {id: value.id}, {name: value.name}, {}) YIELD node
    RETURN count(node) AS nodes_created;
    
    // Nhập Edge
    CALL apoc.load.json("file:///edges_clean.json") YIELD value
    MATCH (source {id: value.source})
    MATCH (target {id: value.target})
    CALL apoc.merge.relationship(
        source, 
        value.type, 
        {}, 
        {
            techniques: coalesce(value.techniques, []), 
            events: coalesce(value.events, []), 
            filters: coalesce(value.filters, []),
            cost: coalesce(value.cost, null)
        }, 
        target
    ) YIELD rel
    RETURN count(rel) AS edges_created;
', {}) YIELD result
RETURN result;