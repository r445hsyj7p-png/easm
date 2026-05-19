import { useState } from "react";
import { Monitor, Network, Server, BarChart2, Code2, Lock, Plus, X, ExternalLink } from "lucide-react";
import { T, alpha } from "../theme";
import { Card, CardHeader, TH, TD, EmptyState, SearchInput, Btn } from "../components/ui/index";
import { FacetedFilter, Pagination } from "../components/ui/FacetedFilter";
import { useApp } from "../context/AppContext";
import { apiFetch } from "../api/client";
import { toast } from "sonner";

const TABS = [
  { id: "hosts",    label: "Hosts",        Icon: Monitor  },
  { id: "ips",      label: "IPs",          Icon: Network  },
  { id: "ports",    label: "Ports",        Icon: Server   },
  { id: "status",   label: "Status Codes", Icon: BarChart2},
  { id: "tech",     label: "Technologies", Icon: Code2    },
  { id: "tls",      label: "TLS",          Icon: Lock     },
];

const PAGE_SIZE = 25;

export default function AssetsNewPage() {
  const { assets, tenantId } = useApp();
  const [tab, setTab]           = useState("hosts");
  const [page, setPage]         = useState(1);
  const [search, setSearch]     = useState("");
  const [filters, setFilters]   = useState({});
  const [showDialog, setDialog] = useState(false);
  const [groupName, setGName]   = useState("");

  const changeTab = t => { setTab(t); setPage(1); setSearch(""); setFilters({}); };
  const updateFilter = (key, val) => { setPage(1); setFilters(f => ({ ...f, [key]: val })); };

  const handleCreateGroup = async () => {
    if (!groupName.trim()) return;
    try {
      await apiFetch(`/tenants/${tenantId}/asset-groups`, {
        method: "POST", body: { name: groupName.trim() },
      });
      toast.success("Gruppe erstellt", { description: groupName.trim() });
      setDialog(false); setGName("");
    } catch (e) {
      toast.error("Fehler", { description: e.message });
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <div style={{ fontFamily: T.fontSans, fontSize: 18, fontWeight: 700, color: T.text0, marginBottom: 4 }}>
            Assets
          </div>
          <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>
            {(assets || []).length} Assets im Inventar
          </div>
        </div>
        <Btn onClick={() => setDialog(true)} variant="secondary">
          <Plus size={12} />Gruppe erstellen
        </Btn>
      </div>

      {/* Tab bar */}
      <div style={{ display: "flex", gap: 0, borderBottom: `1px solid ${T.border}` }}>
        {TABS.map(t => {
          const active = tab === t.id;
          return (
            <button key={t.id} onClick={() => changeTab(t.id)} style={{
              display: "flex", alignItems: "center", gap: 6,
              padding: "10px 16px", background: "transparent", border: "none",
              borderBottom: `2px solid ${active ? T.accent : "transparent"}`,
              fontFamily: T.fontSans, fontSize: 13, fontWeight: active ? 600 : 400,
              color: active ? T.accent : T.text2, cursor: "pointer",
              transition: "color 0.12s", marginBottom: -1,
            }}>
              <t.Icon size={13} />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      {tab === "hosts"  && <HostsTab  assets={assets} search={search} setSearch={setSearch} filters={filters} updateFilter={updateFilter} page={page} setPage={setPage} />}
      {tab === "ips"    && <IpsTab    assets={assets} search={search} setSearch={setSearch} filters={filters} updateFilter={updateFilter} page={page} setPage={setPage} />}
      {tab === "ports"  && <PortsTab  assets={assets} search={search} setSearch={setSearch} filters={filters} updateFilter={updateFilter} page={page} setPage={setPage} />}
      {tab === "status" && <StatusTab assets={assets} search={search} setSearch={setSearch} filters={filters} updateFilter={updateFilter} page={page} setPage={setPage} />}
      {tab === "tech"   && <TechTab   assets={assets} search={search} setSearch={setSearch} filters={filters} updateFilter={updateFilter} page={page} setPage={setPage} />}
      {tab === "tls"    && <TlsTab    assets={assets} search={search} setSearch={setSearch} filters={filters} updateFilter={updateFilter} page={page} setPage={setPage} />}

      {/* Create group dialog */}
      {showDialog && (
        <div style={{
          position: "fixed", inset: 0, zIndex: 300,
          background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center",
        }} onClick={() => setDialog(false)}>
          <div onClick={e => e.stopPropagation()} style={{
            background: T.bg2, border: `1px solid ${T.border}`,
            borderRadius: 10, padding: 24, width: 380, boxShadow: "0 20px 60px rgba(0,0,0,0.5)",
          }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
              <div style={{ fontFamily: T.fontSans, fontSize: 14, fontWeight: 700, color: T.text0 }}>
                Asset-Gruppe erstellen
              </div>
              <button onClick={() => setDialog(false)} style={{
                background: "none", border: "none", color: T.text3, cursor: "pointer",
              }}><X size={16} /></button>
            </div>
            <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text2, marginBottom: 8 }}>
              Gruppenname
            </div>
            <input
              autoFocus
              value={groupName}
              onChange={e => setGName(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleCreateGroup()}
              placeholder="z.B. Produktion, DMZ, Cloud…"
              style={{
                width: "100%", boxSizing: "border-box",
                padding: "9px 12px", background: T.bg3, border: `1px solid ${T.border}`,
                borderRadius: 6, fontFamily: T.font, fontSize: 12, color: T.text0,
                outline: "none", marginBottom: 16,
              }}
            />
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <Btn onClick={() => setDialog(false)} variant="ghost">Abbrechen</Btn>
              <Btn onClick={handleCreateGroup} variant="primary" disabled={!groupName.trim()}>Erstellen</Btn>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Shared filter bar ── */
function FilterBar({ search, setSearch, children }) {
  return (
    <div style={{
      display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center",
      padding: "12px 16px", borderBottom: `1px solid ${T.border}`,
    }}>
      <SearchInput value={search} onChange={v => setSearch(v)} placeholder="Suchen…" width={220} />
      <div style={{ width: 1, height: 20, background: T.border }} />
      {children}
    </div>
  );
}

/* ── Hosts tab ── */
function HostsTab({ assets, search, setSearch, filters, updateFilter, page, setPage }) {
  const rows = (assets || []).filter(a => a.fqdn || a.subdomain);
  const STATUS_OPTS = [
    { value: "200", label: "200 OK" },
    { value: "301", label: "3xx Redirect" },
    { value: "403", label: "403 Forbidden" },
    { value: "404", label: "404 Not Found" },
  ];
  const statusCounts = STATUS_OPTS.map(o => ({ ...o, count: rows.filter(r => String(r.status_code || "200").startsWith(o.value[0])).length }));

  const filtered = rows.filter(r => {
    const q = search.toLowerCase();
    const matchS = !search || (r.fqdn || r.subdomain || "").toLowerCase().includes(q);
    const matchStatus = !filters.status_code?.length || filters.status_code.includes(String(r.status_code || "200").slice(0,1) + "xx");
    return matchS && matchStatus;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged      = filtered.slice((page-1)*PAGE_SIZE, page*PAGE_SIZE);

  return (
    <Card>
      <FilterBar search={search} setSearch={v => { setSearch(v); setPage(1); }}>
        <FacetedFilter label="Status Code" options={statusCounts} value={filters.status_code || []}
          onChange={v => updateFilter("status_code", v)} />
        <span style={{ marginLeft: "auto", fontFamily: T.font, fontSize: 10, color: T.text3 }}>
          {filtered.length} Hosts
        </span>
      </FilterBar>
      {paged.length === 0 ? (
        <EmptyState icon={Monitor} title="Keine Hosts" sub="Noch kein Scan oder kein Ergebnis für diesen Filter." />
      ) : (
        <>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <TH>Screenshot</TH>
                  <TH>Host</TH>
                  <TH>IP</TH>
                  <TH>Status</TH>
                  <TH>Titel</TH>
                  <TH>Letzter Scan</TH>
                </tr>
              </thead>
              <tbody>
                {paged.map((r, i) => (
                  <tr key={i} style={{ transition: "background 0.1s" }}
                    onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                  >
                    <TD style={{ width: 80 }}>
                      {r.screenshot_url ? (
                        <div style={{
                          width: 72, height: 44, borderRadius: 4, overflow: "hidden",
                          border: `1px solid ${T.border}`, flexShrink: 0,
                        }}>
                          <img src={r.screenshot_url} alt="" style={{ width: "100%", height: "100%", objectFit: "cover" }} />
                        </div>
                      ) : (
                        <div style={{
                          width: 72, height: 44, borderRadius: 4,
                          background: T.bg3, border: `1px solid ${T.border}`,
                          display: "flex", alignItems: "center", justifyContent: "center",
                        }}>
                          <Monitor size={14} color={T.text4} />
                        </div>
                      )}
                    </TD>
                    <TD>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <span style={{ fontFamily: T.font, fontSize: 11, color: T.accent, fontWeight: 600 }}>
                          {r.fqdn || r.subdomain}
                        </span>
                        {r.url && (
                          <a href={r.url} target="_blank" rel="noopener noreferrer" style={{ color: T.text3 }}>
                            <ExternalLink size={10} />
                          </a>
                        )}
                      </div>
                    </TD>
                    <TD style={{ fontFamily: T.font, fontSize: 11, color: T.text2 }}>{r.ip || "—"}</TD>
                    <TD>
                      <StatusCodeBadge code={r.status_code} />
                    </TD>
                    <TD style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text2, maxWidth: 200 }}>
                      <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {r.title || "—"}
                      </div>
                    </TD>
                    <TD style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3 }}>
                      {r.last_seen ? new Date(r.last_seen).toLocaleDateString("de-DE") : "—"}
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
  );
}

/* ── IPs tab ── */
function IpsTab({ assets, search, setSearch, filters, updateFilter, page, setPage }) {
  const rows = (assets || []).filter(a => a.ip);

  const CLOUD_OPTS = [
    { value: "aws",   label: "AWS"   },
    { value: "azure", label: "Azure" },
    { value: "gcp",   label: "GCP"   },
    { value: "other", label: "Other" },
  ];
  const cloudCounts = CLOUD_OPTS.map(o => ({ ...o, count: rows.filter(r => (r.cloud || "other") === o.value).length }));

  const filtered = rows.filter(r => {
    const q = search.toLowerCase();
    const matchS = !search || r.ip.includes(q) || (r.org || "").toLowerCase().includes(q);
    const matchCloud = !filters.cloud?.length || filters.cloud.includes(r.cloud || "other");
    return matchS && matchCloud;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged      = filtered.slice((page-1)*PAGE_SIZE, page*PAGE_SIZE);

  return (
    <Card>
      <FilterBar search={search} setSearch={v => { setSearch(v); setPage(1); }}>
        <FacetedFilter label="Cloud" options={cloudCounts} value={filters.cloud || []}
          onChange={v => updateFilter("cloud", v)} />
        <span style={{ marginLeft: "auto", fontFamily: T.font, fontSize: 10, color: T.text3 }}>
          {filtered.length} IPs
        </span>
      </FilterBar>
      {paged.length === 0 ? (
        <EmptyState icon={Network} title="Keine IPs" sub="Noch kein Scan oder kein Ergebnis für diesen Filter." />
      ) : (
        <>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <TH>IP</TH>
                  <TH>Organisation</TH>
                  <TH>ASN</TH>
                  <TH>Land</TH>
                  <TH>Cloud</TH>
                  <TH>Ports</TH>
                </tr>
              </thead>
              <tbody>
                {paged.map((r, i) => (
                  <tr key={i} style={{ transition: "background 0.1s" }}
                    onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                  >
                    <TD style={{ fontFamily: T.font, fontSize: 11, color: T.accent, fontWeight: 600 }}>{r.ip}</TD>
                    <TD style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1 }}>{r.org || "—"}</TD>
                    <TD style={{ fontFamily: T.font, fontSize: 10, color: T.text3 }}>
                      {r.asn ? `AS${r.asn}` : "—"}
                    </TD>
                    <TD style={{ fontFamily: T.font, fontSize: 11, color: T.text2 }}>{r.country || "—"}</TD>
                    <TD>
                      {r.cloud ? (
                        <span style={{
                          fontFamily: T.font, fontSize: 9, color: T.medium,
                          background: T.mediumBg, border: `1px solid ${T.mediumBorder}`,
                          padding: "1px 6px", borderRadius: 3,
                        }}>{r.cloud.toUpperCase()}</span>
                      ) : <span style={{ color: T.text4, fontFamily: T.font, fontSize: 11 }}>—</span>}
                    </TD>
                    <TD style={{ fontFamily: T.font, fontSize: 11, color: T.text2 }}>
                      {r.open_ports?.length ? r.open_ports.slice(0, 6).join(", ") + (r.open_ports.length > 6 ? "…" : "") : "—"}
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
  );
}

/* ── Ports tab ── */
function PortsTab({ assets, search, setSearch, filters, updateFilter, page, setPage }) {
  const portMap = {};
  (assets || []).forEach(a => {
    (a.open_ports || []).forEach(p => {
      if (!portMap[p]) portMap[p] = { port: p, count: 0, hosts: [] };
      portMap[p].count++;
      portMap[p].hosts.push(a.fqdn || a.ip || "");
    });
  });
  const rows = Object.values(portMap).sort((a, b) => b.count - a.count);

  const COMMON = { 80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB" };

  const filtered = rows.filter(r => {
    const q = search.toLowerCase();
    return !search || String(r.port).includes(q) || (COMMON[r.port] || "").toLowerCase().includes(q);
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged      = filtered.slice((page-1)*PAGE_SIZE, page*PAGE_SIZE);

  return (
    <Card>
      <FilterBar search={search} setSearch={v => { setSearch(v); setPage(1); }}>
        <span style={{ marginLeft: "auto", fontFamily: T.font, fontSize: 10, color: T.text3 }}>
          {filtered.length} Ports
        </span>
      </FilterBar>
      {paged.length === 0 ? (
        <EmptyState icon={Server} title="Keine Ports" sub="Noch kein Port-Scan durchgeführt." />
      ) : (
        <>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <TH>Port</TH>
                  <TH>Protokoll</TH>
                  <TH>Service</TH>
                  <TH>Hosts</TH>
                </tr>
              </thead>
              <tbody>
                {paged.map((r, i) => (
                  <tr key={i} style={{ transition: "background 0.1s" }}
                    onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                  >
                    <TD style={{ fontFamily: T.font, fontSize: 12, color: T.accent, fontWeight: 700 }}>{r.port}</TD>
                    <TD style={{ fontFamily: T.font, fontSize: 11, color: T.text3 }}>TCP</TD>
                    <TD>
                      {COMMON[r.port] ? (
                        <span style={{
                          fontFamily: T.font, fontSize: 9, color: T.info,
                          background: T.infoBg, border: `1px solid ${T.infoBorder}`,
                          padding: "1px 6px", borderRadius: 3,
                        }}>{COMMON[r.port]}</span>
                      ) : <span style={{ color: T.text4, fontFamily: T.font, fontSize: 11 }}>—</span>}
                    </TD>
                    <TD style={{ fontFamily: T.font, fontSize: 12, color: T.accent, fontWeight: 700 }}>{r.count}</TD>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} totalPages={totalPages} onPage={setPage} />
        </>
      )}
    </Card>
  );
}

/* ── Status Codes tab ── */
function StatusTab({ assets, search, setSearch, page, setPage }) {
  const statusMap = {};
  (assets || []).forEach(a => {
    const code = a.status_code || 200;
    if (!statusMap[code]) statusMap[code] = { code, count: 0 };
    statusMap[code].count++;
  });
  const rows = Object.values(statusMap).sort((a, b) => b.count - a.count);

  const filtered = rows.filter(r => !search || String(r.code).includes(search));
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged      = filtered.slice((page-1)*PAGE_SIZE, page*PAGE_SIZE);

  const totalCount = rows.reduce((s, r) => s + r.count, 0);

  return (
    <Card>
      <FilterBar search={search} setSearch={v => { setSearch(v); setPage(1); }}>
        <span style={{ marginLeft: "auto", fontFamily: T.font, fontSize: 10, color: T.text3 }}>
          {filtered.length} Status-Codes
        </span>
      </FilterBar>
      {paged.length === 0 ? (
        <EmptyState icon={BarChart2} title="Keine Status-Codes" sub="Noch kein Web-Scan durchgeführt." />
      ) : (
        <>
          <div style={{ padding: "16px 20px", display: "flex", flexDirection: "column", gap: 8 }}>
            {paged.map((r, i) => {
              const pct = totalCount > 0 ? (r.count / totalCount) * 100 : 0;
              return (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <StatusCodeBadge code={r.code} />
                  <div style={{ flex: 1, height: 6, background: T.bg3, borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ width: `${pct}%`, height: "100%", background: statusCodeColor(r.code), borderRadius: 3 }} />
                  </div>
                  <span style={{ fontFamily: T.font, fontSize: 11, color: T.text2, minWidth: 32, textAlign: "right" }}>
                    {r.count}
                  </span>
                </div>
              );
            })}
          </div>
          <Pagination page={page} totalPages={totalPages} onPage={setPage} />
        </>
      )}
    </Card>
  );
}

/* ── Technologies tab ── */
function TechTab({ assets, search, setSearch, page, setPage }) {
  const techMap = {};
  (assets || []).forEach(a => {
    (a.technologies || []).forEach(t => {
      const key = typeof t === "string" ? t : t.name || t;
      if (!techMap[key]) techMap[key] = { name: key, count: 0, category: typeof t === "object" ? t.category : null };
      techMap[key].count++;
    });
  });
  const rows = Object.values(techMap).sort((a, b) => b.count - a.count);

  const filtered = rows.filter(r => !search || r.name.toLowerCase().includes(search.toLowerCase()));
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged      = filtered.slice((page-1)*PAGE_SIZE, page*PAGE_SIZE);

  return (
    <Card>
      <FilterBar search={search} setSearch={v => { setSearch(v); setPage(1); }}>
        <span style={{ marginLeft: "auto", fontFamily: T.font, fontSize: 10, color: T.text3 }}>
          {filtered.length} Technologies
        </span>
      </FilterBar>
      {paged.length === 0 ? (
        <EmptyState icon={Code2} title="Keine Technologien" sub="Noch kein Web-Scan mit Tech-Erkennung durchgeführt." />
      ) : (
        <>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <TH>Technologie</TH>
                  <TH>Kategorie</TH>
                  <TH>Hosts</TH>
                </tr>
              </thead>
              <tbody>
                {paged.map((r, i) => (
                  <tr key={i} style={{ transition: "background 0.1s" }}
                    onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                  >
                    <TD style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text0, fontWeight: 500 }}>{r.name}</TD>
                    <TD>
                      {r.category ? (
                        <span style={{
                          fontFamily: T.font, fontSize: 9, color: T.text2,
                          background: T.bg4, border: `1px solid ${T.border}`,
                          padding: "1px 6px", borderRadius: 3,
                        }}>{r.category}</span>
                      ) : <span style={{ color: T.text4, fontFamily: T.font, fontSize: 11 }}>—</span>}
                    </TD>
                    <TD style={{ fontFamily: T.font, fontSize: 12, color: T.accent, fontWeight: 700 }}>{r.count}</TD>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} totalPages={totalPages} onPage={setPage} />
        </>
      )}
    </Card>
  );
}

/* ── TLS tab ── */
function TlsTab({ assets, search, setSearch, filters, updateFilter, page, setPage }) {
  const rows = (assets || []).filter(a => a.tls || a.ssl);

  const GRADE_OPTS = ["A+","A","B","C","D","F"].map(g => ({
    value: g, label: g,
    count: rows.filter(r => (r.tls?.grade || r.ssl?.grade) === g).length,
  }));

  const filtered = rows.filter(r => {
    const q = search.toLowerCase();
    const host = r.fqdn || r.subdomain || r.ip || "";
    const matchS = !search || host.toLowerCase().includes(q);
    const grade  = r.tls?.grade || r.ssl?.grade;
    const matchG = !filters.grade?.length || filters.grade.includes(grade);
    return matchS && matchG;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged      = filtered.slice((page-1)*PAGE_SIZE, page*PAGE_SIZE);

  return (
    <Card>
      <FilterBar search={search} setSearch={v => { setSearch(v); setPage(1); }}>
        <FacetedFilter label="Grade" options={GRADE_OPTS} value={filters.grade || []}
          onChange={v => updateFilter("grade", v)} />
        <span style={{ marginLeft: "auto", fontFamily: T.font, fontSize: 10, color: T.text3 }}>
          {filtered.length} TLS-Hosts
        </span>
      </FilterBar>
      {paged.length === 0 ? (
        <EmptyState icon={Lock} title="Keine TLS-Daten" sub="Noch kein TLS-Scan durchgeführt." />
      ) : (
        <>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <TH>Host</TH>
                  <TH>Grade</TH>
                  <TH>Protokoll</TH>
                  <TH>Läuft ab</TH>
                  <TH>Aussteller</TH>
                </tr>
              </thead>
              <tbody>
                {paged.map((r, i) => {
                  const tls = r.tls || r.ssl || {};
                  return (
                    <tr key={i} style={{ transition: "background 0.1s" }}
                      onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      <TD style={{ fontFamily: T.font, fontSize: 11, color: T.accent, fontWeight: 600 }}>
                        {r.fqdn || r.subdomain || r.ip}
                      </TD>
                      <TD><TlsGradeBadge grade={tls.grade} /></TD>
                      <TD style={{ fontFamily: T.font, fontSize: 10, color: T.text2 }}>{tls.protocol || "—"}</TD>
                      <TD style={{ fontFamily: T.fontSans, fontSize: 11, color: tls.days_remaining < 30 ? T.critical : T.text2 }}>
                        {tls.expires ? new Date(tls.expires).toLocaleDateString("de-DE") : "—"}
                        {tls.days_remaining != null && (
                          <span style={{ marginLeft: 6, fontFamily: T.font, fontSize: 9, color: T.text3 }}>
                            ({tls.days_remaining}d)
                          </span>
                        )}
                      </TD>
                      <TD style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text2 }}>{tls.issuer || "—"}</TD>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <Pagination page={page} totalPages={totalPages} onPage={setPage} />
        </>
      )}
    </Card>
  );
}

/* ── Helpers ── */
function statusCodeColor(code) {
  const c = Number(code);
  if (c >= 500) return T.critical;
  if (c >= 400) return T.high;
  if (c >= 300) return T.medium;
  if (c >= 200) return T.accent;
  return T.text3;
}

function StatusCodeBadge({ code }) {
  const color = statusCodeColor(code);
  return (
    <span style={{
      fontFamily: T.font, fontSize: 9, fontWeight: 700, color,
      background: alpha(color, 10), border: `1px solid ${alpha(color, 25)}`,
      padding: "1px 6px", borderRadius: 3,
    }}>{code || 200}</span>
  );
}

function TlsGradeBadge({ grade }) {
  const colors = { "A+": T.accent, A: T.accent, B: T.low, C: T.medium, D: T.high, F: T.critical };
  const color = colors[grade] || T.text3;
  return (
    <span style={{
      fontFamily: T.font, fontSize: 10, fontWeight: 700, color,
      background: alpha(color, 10), border: `1px solid ${alpha(color, 25)}`,
      padding: "1px 8px", borderRadius: 3,
    }}>{grade || "—"}</span>
  );
}
