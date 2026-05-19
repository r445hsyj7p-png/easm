import { useState, useMemo } from "react";
import { Globe, Server, Network } from "lucide-react";
import { T, SEV } from "../theme";
import { KpiCard, Card, CardHeader, TH, TD, SevBadge, SearchInput, EmptyState, PageLoading, FilterPill } from "../components/ui/index";
import { useApp } from "../context/AppContext";

export default function AssetsPage() {
  const { assets, findings, tenant, loading } = useApp();
  const [search, setSearch]       = useState("");
  const [sort, setSort]           = useState({ col: "fqdn", dir: "asc" });
  const [riskFilter, setRiskFilter] = useState("ALL");

  if (loading) return <PageLoading />;

  const assetList = assets || [];

  // Map findings risk onto assets
  const assetRisk = useMemo(() => {
    const map = {};
    const sev_ord = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    for (const f of (findings || [])) {
      if (!f.asset || f.status !== "open") continue;
      const cur = map[f.asset];
      if (!cur || (sev_ord[f.sev] ?? 9) < (sev_ord[cur] ?? 9)) map[f.asset] = f.sev;
    }
    return map;
  }, [findings]);

  const filtered = useMemo(() => {
    return assetList
      .map(a => ({ ...a, riskLevel: assetRisk[a.fqdn || a.subdomain] || "INFO" }))
      .filter(a => {
        const fqdn = a.fqdn || a.subdomain || "";
        const ip   = a.ip || "";
        const org  = a.org || a.organization || "";
        const matchSearch = !search ||
          fqdn.toLowerCase().includes(search.toLowerCase()) ||
          ip.includes(search) ||
          org.toLowerCase().includes(search.toLowerCase());
        const matchRisk = riskFilter === "ALL" || a.riskLevel === riskFilter;
        return matchSearch && matchRisk;
      })
      .sort((a, b) => {
        let cmp = 0;
        if (sort.col === "fqdn") cmp = (a.fqdn || a.subdomain || "").localeCompare(b.fqdn || b.subdomain || "");
        if (sort.col === "ip")   cmp = (a.ip || "").localeCompare(b.ip || "");
        if (sort.col === "org")  cmp = (a.org || "").localeCompare(b.org || "");
        if (sort.col === "risk") {
          const so = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };
          cmp = (so[a.riskLevel] ?? 9) - (so[b.riskLevel] ?? 9);
        }
        return sort.dir === "asc" ? cmp : -cmp;
      });
  }, [assetList, search, sort, riskFilter, assetRisk]);

  const toggleSort = col => setSort(s => s.col === col ? { col, dir: s.dir === "asc" ? "desc" : "asc" } : { col, dir: "asc" });

  const uniqueIPs   = new Set(assetList.map(a => a.ip).filter(Boolean)).size;
  const totalPorts  = assetList.reduce((s, a) => s + (a.ports?.length || 0), 0);
  const critCount   = Object.values(assetRisk).filter(r => r === "CRITICAL" || r === "HIGH").length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* KPIs */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
        <KpiCard label="Subdomains" value={assetList.length} icon={Globe} color={T.accent} />
        <KpiCard label="Unique IPs" value={uniqueIPs} icon={Server} color={T.low} />
        <KpiCard label="Offene Ports" value={totalPorts} icon={Network} />
        <KpiCard
          label="Gefährdete Assets" value={critCount}
          color={critCount > 0 ? T.critical : T.text2}
          sub="CRITICAL oder HIGH Findings"
        />
      </div>

      {/* Table */}
      <Card>
        <CardHeader
          title="Asset-Inventar"
          sub={`${filtered.length} von ${assetList.length} Assets`}
        />

        {/* Filter bar */}
        <div style={{
          display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center",
          padding: "12px 16px", borderBottom: `1px solid ${T.border}`,
        }}>
          <SearchInput value={search} onChange={setSearch} placeholder="FQDN, IP, Organisation…" width={240} />
          <div style={{ width: 1, height: 20, background: T.border }} />
          <FilterPill label="Alle" active={riskFilter === "ALL"} onClick={() => setRiskFilter("ALL")} />
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
            <FilterPill key={s} label={s} active={riskFilter === s}
              color={SEV[s]?.color} onClick={() => setRiskFilter(riskFilter === s ? "ALL" : s)} />
          ))}
        </div>

        {filtered.length === 0 ? (
          <EmptyState title="Keine Assets" sub="Noch kein Scan durchgeführt oder keine Ergebnisse für diesen Filter." />
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <TH onClick={() => toggleSort("fqdn")} sorted={sort.col === "fqdn"}>FQDN</TH>
                  <TH onClick={() => toggleSort("ip")} sorted={sort.col === "ip"}>IP</TH>
                  <TH onClick={() => toggleSort("org")} sorted={sort.col === "org"}>Organisation</TH>
                  <TH>Land</TH>
                  <TH>Ports</TH>
                  <TH onClick={() => toggleSort("risk")} sorted={sort.col === "risk"}>Risiko</TH>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a, i) => {
                  const fqdn  = a.fqdn || a.subdomain || "—";
                  const ip    = a.ip || "—";
                  const org   = a.org || a.organization || "—";
                  const country = a.country || "—";
                  const ports = a.ports || [];
                  const sevStyle = SEV[a.riskLevel] || SEV.INFO;
                  return (
                    <tr key={`${fqdn}-${i}`} style={{ transition: "background 0.1s" }}
                      onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      <TD style={{ fontFamily: T.font, fontSize: 11, color: T.accent }}>
                        {fqdn}
                      </TD>
                      <TD style={{ fontFamily: T.font, fontSize: 11, color: T.text2 }}>
                        {ip}
                      </TD>
                      <TD style={{ maxWidth: 200 }}>
                        <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {org}
                        </div>
                        {a.asn && (
                          <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, marginTop: 2 }}>AS{a.asn}</div>
                        )}
                      </TD>
                      <TD>
                        <span style={{ fontFamily: T.font, fontSize: 11, color: T.text2 }}>{country}</span>
                      </TD>
                      <TD>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                          {ports.length === 0 ? (
                            <span style={{ fontFamily: T.font, fontSize: 10, color: T.text4 }}>—</span>
                          ) : ports.slice(0, 6).map(p => (
                            <span key={p} style={{
                              fontFamily: T.font, fontSize: 10, color: T.low,
                              background: T.lowBg, border: `1px solid ${T.lowBorder}`,
                              padding: "0 5px", borderRadius: 3,
                            }}>{p}</span>
                          ))}
                          {ports.length > 6 && (
                            <span style={{ fontFamily: T.font, fontSize: 10, color: T.text3 }}>+{ports.length - 6}</span>
                          )}
                        </div>
                      </TD>
                      <TD>
                        {a.riskLevel !== "INFO" ? (
                          <SevBadge sev={a.riskLevel} small />
                        ) : (
                          <span style={{ fontFamily: T.font, fontSize: 10, color: T.text4 }}>—</span>
                        )}
                      </TD>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
