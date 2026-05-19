import { useState } from "react";
import { toast } from "sonner";
import { Target, Play, RefreshCw } from "lucide-react";
import { T } from "../theme";
import { Card, TH, TD, SevBadge, EmptyState, SearchInput, Btn } from "../components/ui/index";
import { FacetedFilter, Pagination } from "../components/ui/FacetedFilter";
import { useApp } from "../context/AppContext";
import { apiFetch } from "../api/client";

const SCOPE_OPTS = [
  { value: "in_scope",     label: "In Scope"     },
  { value: "out_of_scope", label: "Out of Scope" },
  { value: "undefined",    label: "Undefined"    },
];
const STATUS_OPTS = [
  { value: "active",   label: "Aktiv"       },
  { value: "inactive", label: "Inaktiv"     },
  { value: "pending",  label: "Ausstehend"  },
];
const TYPE_OPTS = [
  { value: "domain",  label: "Domain"  },
  { value: "ip",      label: "IP"      },
  { value: "cidr",    label: "CIDR"    },
  { value: "url",     label: "URL"     },
];
const PAGE_SIZE = 25;

export default function TargetsPage() {
  const { assets, tenantId } = useApp();

  const [search,      setSearch]      = useState("");
  const [scopeFilter, setScopeFilter] = useState([]);
  const [statusFilter,setStatusFilter]= useState([]);
  const [typeFilter,  setTypeFilter]  = useState([]);
  const [page,        setPage]        = useState(1);
  const [starting,    setStarting]    = useState(false);

  // Derive targets from assets until a dedicated /targets endpoint exists
  const allTargets = (assets || []).map(a => ({
    id:        a.id || a.fqdn || a.subdomain,
    name:      a.fqdn || a.subdomain || a.ip || "—",
    type:      a.fqdn ? "domain" : "ip",
    scope:     a.scope || "in_scope",
    status:    a.status || "active",
    assetCount:1,
    lastScan:  a.last_seen || null,
  }));

  const filtered = allTargets.filter(t => {
    const q = search.toLowerCase();
    const matchSearch = !search || t.name.toLowerCase().includes(q);
    const matchScope  = scopeFilter.length  === 0 || scopeFilter.includes(t.scope);
    const matchStatus = statusFilter.length === 0 || statusFilter.includes(t.status);
    const matchType   = typeFilter.length   === 0 || typeFilter.includes(t.type);
    return matchSearch && matchScope && matchStatus && matchType;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged      = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const handleDiscover = async () => {
    setStarting(true);
    try {
      await apiFetch(`/tenants/${tenantId}/scans`, { method: "POST", body: { scan_type: "full" } });
      toast.success("Discovery gestartet", { description: "Full-Scan läuft im Hintergrund." });
    } catch (e) {
      toast.error("Fehler", { description: e.message });
    } finally {
      setStarting(false);
    }
  };

  const scopeCounts = SCOPE_OPTS.map(o => ({
    ...o, count: allTargets.filter(t => t.scope === o.value).length,
  }));
  const statusCounts = STATUS_OPTS.map(o => ({
    ...o, count: allTargets.filter(t => t.status === o.value).length,
  }));
  const typeCounts = TYPE_OPTS.map(o => ({
    ...o, count: allTargets.filter(t => t.type === o.value).length,
  }));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <div style={{ fontFamily: T.fontSans, fontSize: 18, fontWeight: 700, color: T.text0, marginBottom: 4 }}>
            Targets
          </div>
          <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>
            {allTargets.length} Ziele im Scope · {filtered.length} gefiltert
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Btn onClick={handleDiscover} variant="primary" disabled={starting}>
            <Play size={12} style={starting ? { animation: "spin 1s linear infinite" } : {}} />
            {starting ? "Startet…" : "Discovery starten"}
          </Btn>
        </div>
      </div>

      <Card>
        {/* Filter bar */}
        <div style={{
          display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center",
          padding: "12px 16px", borderBottom: `1px solid ${T.border}`,
        }}>
          <SearchInput value={search} onChange={v => { setSearch(v); setPage(1); }} placeholder="Name, IP, Domain…" width={220} />
          <div style={{ width: 1, height: 20, background: T.border }} />
          <FacetedFilter label="Scope"  options={scopeCounts}  value={scopeFilter}  onChange={v => { setScopeFilter(v);  setPage(1); }} />
          <FacetedFilter label="Status" options={statusCounts} value={statusFilter} onChange={v => { setStatusFilter(v); setPage(1); }} />
          <FacetedFilter label="Typ"    options={typeCounts}   value={typeFilter}   onChange={v => { setTypeFilter(v);   setPage(1); }} />
          <span style={{ marginLeft: "auto", fontFamily: T.font, fontSize: 10, color: T.text3 }}>
            {filtered.length} Ergebnisse
          </span>
        </div>

        {/* Table */}
        {paged.length === 0 ? (
          <EmptyState icon={Target} title="Keine Targets" sub="Noch kein Asset-Scan durchgeführt oder kein Ergebnis für diesen Filter." />
        ) : (
          <>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    <TH>Name</TH>
                    <TH>Typ</TH>
                    <TH>Scope</TH>
                    <TH>Status</TH>
                    <TH>Assets</TH>
                    <TH>Letzter Scan</TH>
                    <TH>Aktionen</TH>
                  </tr>
                </thead>
                <tbody>
                  {paged.map(t => (
                    <tr key={t.id}
                      style={{ transition: "background 0.1s" }}
                      onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      <TD style={{ fontFamily: T.font, fontSize: 11, color: T.accent, fontWeight: 600 }}>
                        {t.name}
                      </TD>
                      <TD>
                        <span style={{
                          fontFamily: T.font, fontSize: 10, color: T.text2,
                          background: T.bg4, border: `1px solid ${T.border}`,
                          padding: "1px 6px", borderRadius: 3,
                        }}>{t.type}</span>
                      </TD>
                      <TD>
                        <ScopeBadge scope={t.scope} />
                      </TD>
                      <TD>
                        <StatusBadge status={t.status} />
                      </TD>
                      <TD style={{ fontFamily: T.font, fontSize: 12, color: T.accent, fontWeight: 700 }}>
                        {t.assetCount}
                      </TD>
                      <TD style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3 }}>
                        {t.lastScan
                          ? new Date(t.lastScan).toLocaleDateString("de-DE")
                          : "—"}
                      </TD>
                      <TD>
                        <button
                          onClick={() => toast.info(`Scan für ${t.name} gestartet`)}
                          style={{
                            display: "flex", alignItems: "center", gap: 4,
                            background: "transparent", border: `1px solid ${T.border}`,
                            borderRadius: 4, padding: "3px 8px", fontFamily: T.font,
                            fontSize: 9, color: T.text2, cursor: "pointer",
                          }}
                        >
                          <RefreshCw size={9} />Scan
                        </button>
                      </TD>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} totalPages={totalPages} onPage={setPage} />
          </>
        )}
      </Card>
    </div>
  );
}

function ScopeBadge({ scope }) {
  const styles = {
    in_scope:     { color: T.accent,   bg: T.accent3,   border: T.accent  },
    out_of_scope: { color: T.critical, bg: T.criticalBg, border: T.criticalBorder },
    undefined:    { color: T.text3,    bg: T.bg4,        border: T.border  },
  };
  const s = styles[scope] || styles.undefined;
  const labels = { in_scope: "In Scope", out_of_scope: "Out of Scope", undefined: "—" };
  return (
    <span style={{
      fontFamily: T.font, fontSize: 9, fontWeight: 700, color: s.color,
      background: s.bg, border: `1px solid ${s.border}`,
      padding: "1px 7px", borderRadius: 3,
    }}>{labels[scope] || scope}</span>
  );
}

function StatusBadge({ status }) {
  const styles = {
    active:   { color: T.accent,  bg: T.accent3,    border: T.accent  },
    inactive: { color: T.text3,   bg: T.bg4,         border: T.border  },
    pending:  { color: T.medium,  bg: T.mediumBg,   border: T.mediumBorder },
  };
  const s = styles[status] || styles.inactive;
  const labels = { active: "Aktiv", inactive: "Inaktiv", pending: "Ausstehend" };
  return (
    <span style={{
      fontFamily: T.font, fontSize: 9, fontWeight: 700, color: s.color,
      background: s.bg, border: `1px solid ${s.border}`,
      padding: "1px 7px", borderRadius: 3,
    }}>{labels[status] || status}</span>
  );
}
