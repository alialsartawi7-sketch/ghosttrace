"""
Intelligence Layer — Entity correlation, confidence scoring, graph building
This is what makes GhostTrace more than just a tool wrapper
"""
from database.manager import EntityDB, Database
from config import Config
from utils.logger import log

class Correlator:
    """Finds and stores relationships between discovered entities"""

    @staticmethod
    def process_result(value, rtype, source, scan_target=None):
        """Analyze a result and create entity relationships"""
        relations = []

        if rtype == "email" and "@" in value:
            domain = value.split("@")[1]
            local = value.split("@")[0]
            EntityDB.add_relation(domain, value, "has_email", 0.9)
            EntityDB.add_relation(value, domain, "belongs_to_domain", 0.9)
            relations.append(f"{domain} → {value}")
            # Local part could be a username
            if local and len(local) > 2 and not local.isdigit():
                EntityDB.add_relation(value, local, "possible_username", 0.4)
                relations.append(f"{value} → username:{local}")

        elif rtype == "username":
            platform = source
            if " @ " in value:
                username = value.split(" @ ")[0].strip()
                platform = value.split(" @ ")[1].strip()
            else:
                username = value
            EntityDB.add_relation(username, platform, "has_account", 0.8)
            if scan_target:
                EntityDB.add_relation(scan_target, value, "linked_profile", 0.6)

        elif rtype == "subdomain":
            host = value.split(" ")[0] if " " in value else value
            parts = host.split(".")
            if len(parts) >= 2:
                main_domain = ".".join(parts[-2:])
                EntityDB.add_relation(main_domain, host, "has_subdomain", 0.9)
                relations.append(f"{main_domain} → {host}")

        elif rtype == "metadata":
            if scan_target:
                EntityDB.add_relation(scan_target, value, "has_metadata", 0.95)

        return relations

class Scorer:
    """Calculates confidence scores based on source reliability and corroboration"""

    @staticmethod
    def calculate(value, source, rtype, existing_count=None):
        """
        Score = base_weight * type_mult * corroboration_bonus
        """
        base = Config.SOURCE_WEIGHTS.get(source, 0.5)
        if existing_count is None:
            from database.manager import ResultDB
            existing_count = ResultDB.count_value(value)
        corroboration = min(1.3, 1.0 + (existing_count * 0.1))
        type_mult = {"email": 0.9, "username": 0.8, "subdomain": 0.85, "metadata": 0.95}.get(rtype, 0.7)
        return round(min(1.0, base * corroboration * type_mult), 2)

    @staticmethod
    def corroboration_bonus(value):
        """Extra bonus if this value was seen in previous scans"""
        from database.manager import ResultDB
        count = ResultDB.count_value(value)
        if count >= 3: return 0.15   # Seen 3+ times across scans
        if count >= 1: return 0.05   # Seen before
        return 0.0                    # First time

class GraphBuilder:
    """Builds graph data for visualization"""

    @staticmethod
    def build(limit=500):
        """Build nodes and edges from entities and relations"""
        nodes = {}; edges = []
        type_colors = {
            "email": "#4f8ef7", "username": "#3ecf8e", "metadata": "#b79af7",
            "subdomain": "#38bdf8", "domain": "#f16060", "source": "#e8a838"
        }
        with Database.connection() as conn:
            # Get entities
            entities = conn.execute(
                "SELECT value,type,scan_count FROM entities ORDER BY last_seen DESC LIMIT ?",
                (limit,)).fetchall()
            for e in entities:
                nodes[e["value"]] = {
                    "id": e["value"], "label": e["value"][:25],
                    "type": e["type"], "color": type_colors.get(e["type"], "#888"),
                    "size": min(12, 5 + e["scan_count"]),
                }
            # Get relations
            rels = conn.execute(
                "SELECT source_entity,target_entity,relation_type,confidence FROM relations ORDER BY confidence DESC LIMIT ?",
                (limit * 2,)).fetchall()
            for r in rels:
                src, tgt = r["source_entity"], r["target_entity"]
                # Ensure both nodes exist
                if src not in nodes:
                    etype = "domain" if "." in src and "@" not in src else "source"
                    nodes[src] = {"id": src, "label": src[:25], "type": etype,
                                 "color": type_colors.get(etype, "#888"), "size": 8}
                if tgt not in nodes:
                    nodes[tgt] = {"id": tgt, "label": tgt[:25], "type": "unknown",
                                 "color": "#888", "size": 5}
                edges.append({
                    "from": src, "to": tgt,
                    "label": r["relation_type"],
                    "weight": r["confidence"]
                })
        return {"nodes": list(nodes.values()), "edges": edges}
