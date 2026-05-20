import { useState, useEffect, useCallback } from "react";
import { toast } from "sonner";
import { X, ExternalLink, CheckCircle, EyeOff } from "lucide-react";
import { T, SEV, SEV_ORDER } from "../theme";
import { SevBadge, StatusBadge, Card, CardHeader, TH, TD, FilterPill, SearchInput, EmptyState, PageLoading, Btn } from "../components/ui/index";
import { Pagination } from "../components/ui/FacetedFilter";
import { useApp } from "../context/AppContext";
import { apiFetch } from "../api/client";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const PAGE_SIZE  = 50;

export default function FindingsPage() {
  const { updateFinding, tenantId } = useApp();

  const [findings,     setFindings]     = useState([]);
  const [fetching,     setFetching]     = useState(true);
  const [sevFilter,    setSevFilter]    = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("open");
  const [kevOnly,      setKevOnly]      = useState(false);
  const [search,       setSearch]       = useState("");
  const [sort,         setSort]         = useState({ col: "sev", dir: "asc" });
  const [selected,     setSelected]     = useState(null);
  const [page,         setPage]         = useState(1);

  // Server-side fetch: re-runs when severity or status filter changes
  const fetchFindings = useCallback(async () => {
    if (!tenantId) return;
    setFetching(true);
    try {
      const params = new URLSearchParams({ limit: 500 });
      if (sevFilter    !== "ALL") params.set("severity", sevFilter);
      if (statusFilter !== "ALL") params.set("status",   statusFilter);
      const data = await apiFetch(`/tenants/${tenantId}/findings?${params}`);
      setFindings(data.findings ?? data);
      setPage(1);
    } catch (e) {
      toast.error("Fehler beim Laden", { description: e.message });
    } finally {
      setFetching(false);
    }
  }, [tenantId, sevFilter, statusFilter]);

  useEffect(() => { fetchFindings(); }, [fetchFindings]);

  const filtered = findings
    .filter(f =>
      (!kevOnly || f.kev) &&
      (!search  ||
        (f.title  || "").toLowerCase().includes(search.toLowerCase()) ||
        (f.asset  || "").toLowerCase().includes(search.toLowerCase()) ||
        (f.tool   || "").toLowerCase().includes(search.toLowerCase()))
    )
    .sort((a, b) => {
      let cmp = 0;
      if (sort.col === "sev")   cmp = (SEV_ORDER[a.sev] ?? 9) - (SEV_ORDER[b.sev] ?? 9);
      if (sort.col === "cvss")  cmp = (b.cvss || 0) - (a.cvss || 0);
      if (sort.col === "epss")  cmp = (parseFloat(b.epss) || 0) - (parseFloat(a.epss) || 0);
      if (sort.col === "age")   cmp = (b.age  || 0) - (a.age  || 0);
      if (sort.col === "title") cmp = (a.title || "").localeCompare(b.title || "");
      if (sort.col === "asset") cmp = (a.asset || "").localeCompare(b.asset || "");
      return sort.dir === "asc" ? cmp : -cmp;
    });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged      = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const toggleSort = col => {
    setSort(s => s.col === col ? { col, dir: s.dir === "asc" ? "desc" : "asc" } : { col, dir: "asc" });
    setPage(1);
  };

  const handleStatus = async (id, newStatus) => {
    try {
      await updateFinding(id, { status: newStatus });
      // Optimistic update in local list
      setFindings(prev => prev.map(f => f.id === id ? { ...f, status: newStatus } : f));
      toast.success(`Finding ${newStatus === "closed" ? "geschlossen" : newStatus === "accepted" ? "akzeptiert" : "geöffnet"}`);
      if (selected?.id === id) setSelected(prev => ({ ...prev, status: newStatus }));
    } catch (e) {
      toast.error("Fehler beim Aktualisieren", { description: e.message });
    }
  };

  if (fetching && findings.length === 0) return <PageLoading />;

  return (
    <div style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
      {/* Main table */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <Card>
          <CardHeader
            title="Findings"
            sub={`${filtered.length} von ${findings.length} · Server-Filter aktiv`}
          />

          {/* Filter bar */}
          <div style={{
            display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center",
            padding: "12px 16px", borderBottom: `1px solid ${T.border}`,
          }}>
            <SearchInput value={search} onChange={v => { setSearch(v); setPage(1); }} placeholder="Titel, Asset, Tool…" width={200} />

            <div style={{ width: 1, height: 20, background: T.border }} />

            {/* Severity — triggers server refetch */}
            <FilterPill label="Alle" active={sevFilter === "ALL"} onClick={() => setSevFilter("ALL")} />
            {SEVERITIES.map(s => (
              <FilterPill key={s} label={s} active={sevFilter === s}
                color={SEV[s]?.color} onClick={() => setSevFilter(sevFilter === s ? "ALL" : s)} />
            ))}

            <div style={{ width: 1, height: 20, background: T.border }} />

            {/* Status — triggers server refetch */}
            <FilterPill label="Offen"       active={statusFilter === "open"}     onClick={() => setStatusFilter(statusFilter === "open"     ? "ALL" : "open")}     />
            <FilterPill label="Geschlossen" active={statusFilter === "closed"}   onClick={() => setStatusFilter(statusFilter === "closed"   ? "ALL" : "closed")}   />
            <FilterPill label="Akzeptiert"  active={statusFilter === "accepted"} onClick={() => setStatusFilter(statusFilter === "accepted" ? "ALL" : "accepted")} />

            <div style={{ width: 1, height: 20, background: T.border }} />

            <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}>
              <input type="checkbox" checked={kevOnly} onChange={e => { setKevOnly(e.target.checked); setPage(1); }} />
              <span style={{ fontFamily: T.font, fontSize: 10, color: kevOnly ? T.red : T.text3 }}>KEV only</span>
            </label>

            {fetching && (
              <span style={{ fontFamily: T.font, fontSize: 10, color: T.text4, marginLeft: "auto" }}>
                Lädt…
              </span>
            )}
          </div>

          {/* Table */}
          {paged.length === 0 ? (
            <EmptyState title="Keine Findings" sub="Keine Findings entsprechen den aktuellen Filtern." />
          ) : (
            <>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <TH onClick={() => toggleSort("sev")}   sorted={sort.col === "sev"}>Sev</TH>
                      <TH onClick={() => toggleSort("title")} sorted={sort.col === "title"}>Titel</TH>
                      <TH onClick={() => toggleSort("asset")} sorted={sort.col === "asset"}>Asset</TH>
                      <TH>Tool</TH>
                      <TH onClick={() => toggleSort("cvss")}  sorted={sort.col === "cvss"}>CVSS</TH>
                      <TH onClick={() => toggleSort("epss")}  sorted={sort.col === "epss"}>EPSS</TH>
                      <TH>Status</TH>
                      <TH onClick={() => toggleSort("age")}   sorted={sort.col === "age"}>Age</TH>
                    </tr>
                  </thead>
                  <tbody>
                    {paged.map(f => (
                      <tr key={f.id}
                        onClick={() => setSelected(selected?.id === f.id ? null : f)}
                        style={{
                          cursor: "pointer",
                          background: selected?.id === f.id ? T.bg3 : "transparent",
                          transition: "background 0.1s",
                        }}
                        onMouseEnter={e => { if (selected?.id !== f.id) e.currentTarget.style.background = T.bg3; }}
                        onMouseLeave={e => { if (selected?.id !== f.id) e.currentTarget.style.background = "transparent"; }}
                      >
                        <TD>
                          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                            <SevBadge sev={f.sev} small />
                            {f.kev && (
                              <span style={{
                                fontFamily: T.font, fontSize: 8, fontWeight: 700,
                                color: T.critical, background: T.criticalBg,
                                border: `1px solid ${T.criticalBorder}`,
                                padding: "0 4px", borderRadius: 2,
                              }}>KEV</span>
                            )}
                          </div>
                        </TD>
                        <TD style={{ maxWidth: 340 }}>
                          <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: T.text0, fontWeight: 500 }}>
                            {f.title}
                          </div>
                          {f.cve && (
                            <div style={{ fontFamily: T.font, fontSize: 10, color: T.text3, marginTop: 2 }}>{f.cve}</div>
                          )}
                        </TD>
                        <TD style={{ maxWidth: 200 }}>
                          <div style={{ fontFamily: T.font, fontSize: 11, color: T.low, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {f.asset || "—"}
                          </div>
                        </TD>
                        <TD>
                          <span style={{
                            fontFamily: T.font, fontSize: 10, color: T.text2,
                            background: T.bg4, border: `1px solid ${T.border}`,
                            padding: "1px 6px", borderRadius: 3,
                          }}>{f.tool || "—"}</span>
                        </TD>
                        <TD>
                          <span style={{ fontFamily: T.font, fontSize: 11, color: f.cvss >= 9 ? T.critical : f.cvss >= 7 ? T.high : T.text2 }}>
                            {f.cvss ? f.cvss.toFixed(1) : "—"}
                          </span>
                        </TD>
                        <TD>
                          <span style={{ fontFamily: T.font, fontSize: 11, color: parseFloat(f.epss) >= 0.5 ? T.critical : T.text2 }}>
                            {f.epss ? parseFloat(f.epss).toFixed(2) : "—"}
                          </span>
                        </TD>
                        <TD><StatusBadge status={f.status} /></TD>
                        <TD>
                          <span style={{ fontFamily: T.font, fontSize: 10, color: T.text3 }}>
                            {f.age != null ? `${f.age}d` : "—"}
                          </span>
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

      {/* Detail drawer */}
      {selected && (
        <div style={{
          width: 380, flexShrink: 0,
          background: T.bg2, border: `1px solid ${T.border}`,
          borderTop: `2px solid ${SEV[selected.sev]?.color || T.border}`,
          borderRadius: 8, overflow: "hidden",
          position: "sticky", top: 0,
          animation: "slideIn 0.15s ease",
        }}>
          <div style={{
            display: "flex", alignItems: "flex-start", gap: 10,
            padding: "14px 16px", borderBottom: `1px solid ${T.border}`,
            background: T.bg3,
          }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6, flexWrap: "wrap" }}>
                <SevBadge sev={selected.sev} />
                <StatusBadge status={selected.status} />
                {selected.kev && (
                  <span style={{
                    fontFamily: T.font, fontSize: 9, fontWeight: 700,
                    color: T.critical, background: T.criticalBg,
                    border: `1px solid ${T.criticalBorder}`, padding: "1px 6px", borderRadius: 2,
                  }}>⚠ KEV</span>
                )}
              </div>
              <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0, lineHeight: 1.4 }}>
                {selected.title}
              </div>
            </div>
            <button onClick={() => setSelected(null)} style={{
              background: "transparent", border: "none", color: T.text3,
              cursor: "pointer", padding: 2, flexShrink: 0,
            }}><X size={16} /></button>
          </div>

          <div style={{ padding: "14px 16px", display: "flex", flexDirection: "column", gap: 14, maxHeight: "calc(100vh - 200px)", overflowY: "auto" }}>
            <Section title="Details">
              <MetaRow label="Asset"     value={selected.asset      || "—"} mono />
              <MetaRow label="Tool"      value={selected.tool       || "—"} />
              <MetaRow label="CVE"       value={selected.cve        || "—"} mono />
              <MetaRow label="CVSS"      value={selected.cvss != null ? `${selected.cvss.toFixed(1)} (${selected.cvss_vector || "—"})` : "—"} />
              <MetaRow label="EPSS"      value={selected.epss != null ? `${parseFloat(selected.epss).toFixed(3)} (${(parseFloat(selected.epss)*100).toFixed(1)}%)` : "—"} />
              <MetaRow label="Alter"     value={selected.age  != null ? `${selected.age} Tage` : "—"} />
              <MetaRow label="Kategorie" value={selected.cat         || "—"} />
            </Section>

            {selected.description && (
              <Section title="Beschreibung">
                <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text1, lineHeight: 1.7 }}>
                  {selected.description}
                </div>
              </Section>
            )}

            {(selected.remediation || selected.fix) && (
              <Section title="Empfohlene Maßnahme">
                <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text1, lineHeight: 1.7 }}>
                  {selected.remediation || selected.fix}
                </div>
              </Section>
            )}

            {selected.references?.length > 0 && (
              <Section title="Referenzen">
                {selected.references.slice(0, 5).map((r, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                    <ExternalLink size={10} color={T.low} />
                    <a href={r} target="_blank" rel="noreferrer" style={{
                      fontFamily: T.font, fontSize: 10, color: T.low,
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 300,
                    }}>{r}</a>
                  </div>
                ))}
              </Section>
            )}

            <Section title="Aktionen">
              {selected.status === "open" ? (
                <div style={{ display: "flex", gap: 8 }}>
                  <Btn onClick={() => handleStatus(selected.id, "closed")} style={{ flex: 1, justifyContent: "center" }}>
                    <CheckCircle size={12} />Schließen
                  </Btn>
                  <Btn onClick={() => handleStatus(selected.id, "accepted")} style={{ flex: 1, justifyContent: "center" }}>
                    <EyeOff size={12} />Akzeptieren
                  </Btn>
                </div>
              ) : (
                <Btn onClick={() => handleStatus(selected.id, "open")} style={{ width: "100%", justifyContent: "center" }}>
                  Wieder öffnen
                </Btn>
              )}
            </Section>
          </div>
        </div>
      )}
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div>
      <div style={{ fontFamily: T.font, fontSize: 9, color: T.text4, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 8 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function MetaRow({ label, value, mono }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", gap: 8, marginBottom: 5 }}>
      <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3, minWidth: 80, flexShrink: 0 }}>{label}</span>
      <span style={{ fontFamily: mono ? T.font : T.fontSans, fontSize: mono ? 10 : 11, color: T.text1, wordBreak: "break-all" }}>
        {value}
      </span>
    </div>
  );
}
