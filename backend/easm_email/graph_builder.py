"""
Neo4j graph builder for email infrastructure analysis.
Uses synchronous driver — safe in Celery tasks.
FastAPI callers wrap public functions in asyncio.to_thread().
"""
from __future__ import annotations
import os
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

_driver = None


def get_driver():
    global _driver
    if _driver is None:
        from neo4j import GraphDatabase
        uri = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "")
        _driver = GraphDatabase.driver(uri, auth=(user, password))
    return _driver


def close_driver() -> None:
    global _driver
    if _driver:
        _driver.close()
        _driver = None


def upsert_analysis(
    domain: str,
    tenant_id: str,
    spf_raw: str | None,
    dmarc_policy_str: str,
    spf_tree,
    mx_servers: list,
    enriched_ips: list,
) -> None:
    driver = get_driver()
    with driver.session() as session:
        session.execute_write(
            _write_analysis,
            domain, tenant_id, spf_raw, dmarc_policy_str,
            spf_tree, mx_servers, enriched_ips,
        )


def _write_analysis(tx, domain, tenant_id, spf_raw, dmarc_policy_str, spf_tree, mx_servers, enriched_ips):
    now = datetime.now(timezone.utc).isoformat()

    tx.run("""
        MERGE (d:Domain {fqdn: $fqdn, tenant_id: $tid})
        SET d.spf_raw = $spf, d.dmarc_policy = $dmarc, d.analyzed_at = $now
    """, fqdn=domain, tid=tenant_id, spf=spf_raw or "", dmarc=dmarc_policy_str, now=now)

    # IP and ASN nodes
    for ip in enriched_ips:
        tx.run("""
            MERGE (i:IP {address: $addr})
            SET i.version = $version, i.ptr = $ptr
        """, addr=ip.address, version=ip.version, ptr=ip.ptr or "")

        if ip.asn:
            tx.run("""
                MERGE (a:ASN {number: $num})
                SET a.name = $name, a.country = $country, a.cidr = $cidr
            """, num=ip.asn.number, name=ip.asn.name,
                   country=ip.asn.country, cidr=ip.asn.cidr)
            tx.run("""
                MATCH (i:IP {address: $addr}), (a:ASN {number: $num})
                MERGE (i)-[:BELONGS_TO]->(a)
            """, addr=ip.address, num=ip.asn.number)

    # MX server nodes and relationships
    for mx in mx_servers:
        tx.run("""
            MERGE (m:MXServer {fqdn: $fqdn})
            SET m.priority = $prio
        """, fqdn=mx.fqdn, prio=mx.priority)
        tx.run("""
            MATCH (d:Domain {fqdn: $domain, tenant_id: $tid}), (m:MXServer {fqdn: $fqdn})
            MERGE (d)-[:HAS_MX {priority: $prio}]->(m)
        """, domain=domain, tid=tenant_id, fqdn=mx.fqdn, prio=mx.priority)
        for ip in mx.ips:
            tx.run("""
                MATCH (m:MXServer {fqdn: $fqdn}), (i:IP {address: $addr})
                MERGE (m)-[:RESOLVES_TO]->(i)
            """, fqdn=mx.fqdn, addr=ip.address)

    # SPF include tree
    if spf_tree:
        _write_spf_node(tx, domain, tenant_id, spf_tree, parent_name=None)


def _write_spf_node(tx, root_domain, tenant_id, node, parent_name):
    # Direct IP authorizations on this node
    for mech in node.mechanisms:
        if mech.type in ("ip4", "ip6") and mech.value:
            cidr_value = mech.value                    # e.g. "203.0.113.0/24" or "1.2.3.4"
            addr = cidr_value.split("/")[0]            # base address used as unique key
            is_network = "/" in cidr_value
            # Store full CIDR as label so the graph shows "203.0.113.0/24" not "203.0.113.0"
            tx.run("""
                MATCH (d:Domain {fqdn: $domain, tenant_id: $tid})
                MERGE (i:IP {address: $addr})
                SET i.version    = CASE WHEN $mtype = 'ip4' THEN 4 ELSE 6 END,
                    i.cidr       = $cidr,
                    i.is_network = $is_net
                MERGE (d)-[:SPF_AUTHORIZES {mechanism: $mtype, qualifier: $qual, cidr: $cidr}]->(i)
            """, domain=root_domain, tid=tenant_id,
                   addr=addr, cidr=cidr_value, is_net=is_network,
                   mtype=mech.type, qual=mech.qualifier)

    # Recursive include/redirect children
    for child in node.children:
        tx.run("""
            MERGE (p:Provider {name: $name})
        """, name=child.domain)

        mech_type = "redirect" if child.is_redirect else "include"

        if parent_name is None:
            tx.run("""
                MATCH (d:Domain {fqdn: $domain, tenant_id: $tid}), (p:Provider {name: $pname})
                MERGE (d)-[:SPF_INCLUDES {depth: $depth, mechanism: $mech}]->(p)
            """, domain=root_domain, tid=tenant_id,
                   pname=child.domain, depth=child.depth, mech=mech_type)
        else:
            tx.run("""
                MATCH (p1:Provider {name: $parent}), (p2:Provider {name: $child})
                MERGE (p1)-[:SPF_INCLUDES {depth: $depth}]->(p2)
            """, parent=parent_name, child=child.domain, depth=child.depth)

        _write_spf_node(tx, root_domain, tenant_id, child, child.domain)


def get_graph_json(domain: str, tenant_id: str) -> dict:
    """Return Cytoscape.js-compatible node/edge lists for a domain."""
    driver = get_driver()
    with driver.session() as session:
        return session.execute_read(_read_graph, domain, tenant_id)


def _read_graph(tx, domain: str, tenant_id: str) -> dict:
    nodes: list[dict] = []
    edges: list[dict] = []
    seen_nodes: set[str] = set()

    def add_node(node_id: str, label: str, node_type: str, extra: dict | None = None):
        if node_id not in seen_nodes:
            data = {"id": node_id, "label": label, "type": node_type}
            if extra:
                data.update(extra)
            nodes.append({"data": data})
            seen_nodes.add(node_id)

    def add_edge(source: str, target: str, label: str, props: dict | None = None):
        edge_id = f"{source}__{label}__{target}"
        data = {"id": edge_id, "source": source, "target": target, "label": label}
        if props:
            data.update(props)
        edges.append({"data": data})

    domain_id = f"domain:{domain}"

    result = tx.run(
        "MATCH (d:Domain {fqdn: $fqdn, tenant_id: $tid}) RETURN d",
        fqdn=domain, tid=tenant_id,
    ).single()
    if not result:
        return {"nodes": [], "edges": []}

    d = result["d"]
    add_node(domain_id, domain, "domain", {"dmarc_policy": d.get("dmarc_policy", "")})

    # SPF includes (Domain → Provider)
    for rec in tx.run("""
        MATCH (d:Domain {fqdn: $fqdn, tenant_id: $tid})-[r:SPF_INCLUDES]->(p:Provider)
        RETURN p.name AS name, r.depth AS depth, r.mechanism AS mech
    """, fqdn=domain, tid=tenant_id):
        pid = f"provider:{rec['name']}"
        add_node(pid, rec["name"], "provider")
        add_edge(domain_id, pid, "SPF_INCLUDES",
                 {"depth": rec["depth"], "mechanism": rec["mech"] or "include"})

    # Provider → Provider (nested includes)
    for rec in tx.run("""
        MATCH (p1:Provider)-[r:SPF_INCLUDES]->(p2:Provider)
        WHERE EXISTS {
            MATCH (d:Domain {fqdn: $fqdn, tenant_id: $tid})-[:SPF_INCLUDES*1..9]->(p1)
        }
        RETURN p1.name AS src, p2.name AS tgt, r.depth AS depth
    """, fqdn=domain, tid=tenant_id):
        src_id, tgt_id = f"provider:{rec['src']}", f"provider:{rec['tgt']}"
        add_node(src_id, rec["src"], "provider")
        add_node(tgt_id, rec["tgt"], "provider")
        add_edge(src_id, tgt_id, "SPF_INCLUDES", {"depth": rec["depth"]})

    # MX servers
    for rec in tx.run("""
        MATCH (d:Domain {fqdn: $fqdn, tenant_id: $tid})-[r:HAS_MX]->(m:MXServer)
        RETURN m.fqdn AS fqdn, r.priority AS prio
    """, fqdn=domain, tid=tenant_id):
        mx_id = f"mx:{rec['fqdn']}"
        add_node(mx_id, rec["fqdn"], "mx_server", {"priority": rec["prio"]})
        add_edge(domain_id, mx_id, "HAS_MX", {"priority": rec["prio"]})

    # MX → IP
    for rec in tx.run("""
        MATCH (d:Domain {fqdn: $fqdn, tenant_id: $tid})-[:HAS_MX]->(m:MXServer)-[:RESOLVES_TO]->(i:IP)
        RETURN m.fqdn AS mx_fqdn, i.address AS ip_addr, i.version AS version,
               coalesce(i.cidr, i.address) AS label
    """, fqdn=domain, tid=tenant_id):
        mx_id = f"mx:{rec['mx_fqdn']}"
        ip_id = f"ip:{rec['ip_addr']}"
        add_node(ip_id, rec["label"], "ip", {"version": rec["version"]})
        add_edge(mx_id, ip_id, "RESOLVES_TO")

    # IP → ASN
    for rec in tx.run("""
        MATCH (d:Domain {fqdn: $fqdn, tenant_id: $tid})-[*1..12]->(i:IP)-[:BELONGS_TO]->(a:ASN)
        RETURN DISTINCT i.address AS ip_addr, a.number AS num, a.name AS name, a.country AS country
        LIMIT 40
    """, fqdn=domain, tid=tenant_id):
        ip_id = f"ip:{rec['ip_addr']}"
        asn_id = f"asn:{rec['num']}"
        add_node(ip_id, rec["ip_addr"], "ip")
        add_node(asn_id, f"AS{rec['num']}", "asn",
                 {"asn_number": rec["num"], "asn_name": rec["name"], "country": rec["country"]})
        add_edge(ip_id, asn_id, "BELONGS_TO")

    return {"nodes": nodes, "edges": edges}


def delete_domain_graph(domain: str, tenant_id: str) -> None:
    """Remove a Domain node and clean up Provider/MXServer nodes that become orphaned."""
    driver = get_driver()
    with driver.session() as session:
        session.execute_write(_delete_domain, domain, tenant_id)


def _delete_domain(tx, domain: str, tenant_id: str) -> None:
    # Collect IDs of related Provider and MXServer nodes before deletion so we
    # can remove those that become orphaned (no remaining relationships).
    # IP and ASN nodes are intentionally kept — they are shared across analyses.
    provider_result = tx.run("""
        MATCH (d:Domain {fqdn: $fqdn, tenant_id: $tid})-[:SPF_INCLUDES*1..10]->(p:Provider)
        RETURN DISTINCT elementId(p) AS pid
    """, fqdn=domain, tid=tenant_id)
    provider_ids = [r["pid"] for r in provider_result]

    mx_result = tx.run("""
        MATCH (d:Domain {fqdn: $fqdn, tenant_id: $tid})-[:HAS_MX]->(m:MXServer)
        RETURN DISTINCT elementId(m) AS mid
    """, fqdn=domain, tid=tenant_id)
    mx_ids = [r["mid"] for r in mx_result]

    # Detach-delete the Domain node (removes all its relationships)
    tx.run("""
        MATCH (d:Domain {fqdn: $fqdn, tenant_id: $tid})
        DETACH DELETE d
    """, fqdn=domain, tid=tenant_id)

    # Delete Provider nodes that are now isolated
    if provider_ids:
        tx.run("""
            MATCH (p:Provider) WHERE elementId(p) IN $ids AND NOT EXISTS((p)--())
            DELETE p
        """, ids=provider_ids)

    # Delete MXServer nodes that are now isolated
    if mx_ids:
        tx.run("""
            MATCH (m:MXServer) WHERE elementId(m) IN $ids AND NOT EXISTS((m)--())
            DELETE m
        """, ids=mx_ids)
