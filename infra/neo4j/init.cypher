// Neo4j schema initialisation for Email Attack Surface Intelligence
// Run once on first startup or via neo4j-admin dbms cypher-shell

// ── Uniqueness constraints ────────────────────────────────────────────────────

CREATE CONSTRAINT domain_unique IF NOT EXISTS
  FOR (d:Domain) REQUIRE (d.fqdn, d.tenant_id) IS UNIQUE;

CREATE CONSTRAINT provider_unique IF NOT EXISTS
  FOR (p:Provider) REQUIRE p.name IS UNIQUE;

CREATE CONSTRAINT ip_unique IF NOT EXISTS
  FOR (i:IP) REQUIRE i.address IS UNIQUE;

CREATE CONSTRAINT asn_unique IF NOT EXISTS
  FOR (a:ASN) REQUIRE a.number IS UNIQUE;

CREATE CONSTRAINT mxserver_unique IF NOT EXISTS
  FOR (m:MXServer) REQUIRE m.fqdn IS UNIQUE;

// ── Lookup indexes ────────────────────────────────────────────────────────────

CREATE INDEX domain_tenant_idx IF NOT EXISTS
  FOR (d:Domain) ON (d.tenant_id);

CREATE INDEX domain_analyzed_idx IF NOT EXISTS
  FOR (d:Domain) ON (d.analyzed_at);

CREATE INDEX ip_address_idx IF NOT EXISTS
  FOR (i:IP) ON (i.address);

CREATE INDEX asn_number_idx IF NOT EXISTS
  FOR (a:ASN) ON (a.number);
