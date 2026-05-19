import { useState } from "react";
import { ShieldAlert, X } from "lucide-react";
import { T, SEV, alpha } from "../theme";
import { Card, TH, TD, SevBadge, EmptyState, SearchInput, Btn } from "../components/ui/index";
import { FacetedFilter, Pagination } from "../components/ui/FacetedFilter";
import { useApp } from "../context/AppContext";
import { apiFetch } from "../api/client";
import { toast } from "sonner";

const PAGE_SIZE = 25;

const SEV_OPTS = [
  { value: "CRITICAL", label: "Critical" },
  { value: "HIGH",     label: "High"     },
  { value: "MEDIUM",   label: "Medium"   },
  { value: "LOW",      label: "Low"      },
  { value: "INFO",     label: "Info"     },
];
const STATUS_OPTS = [
  { value: "open",     label: "Offen"      },
  { value: "closed",   label: "Geschlossen"},
  { value: "accepted", label: "Akzeptiert" },
  { value: "fp",       label: "False Positive" },
];

export default function VulnerabilitiesPage() {
  const { findings, tenantId, reload } = useApp();
  const [search,       setSearch]      = useState("");
  const [sevFilter,    setSevFilter]   = useState([]);
  const [statusFilter, setStatusFilter]= useState([]);
  const [tagFilter,    setTagFilter]   = useState([]);
  const [page,         setPage]        = useState(1);
  const [dismiss,      setDismiss]     = useState(null); // { finding, comment }

  // Map findings to vulnerabilities (reuse findings data until dedicated endpoint)
  const vulns = (findings || []).map(f => ({
    id:       f.id,
    title:    f.title || f.type || "Unknown",
    severity: (f.severity || "INFO").toUpperCase(),
    target:   f.target || f.host || "—",
    asset:    f.fqdn || f.subdomain || f.ip || "—",
    status:   f.status || "open",
    date:     f.created_at || f.first_seen || null,
    tags:     f.tags || [],
    raw:      f,
  }));

  // Derive tag options
  const allTags = [...new Set(vulns.flatMap(v => v.tags))].sort();
  const tagOpts = allTags.map(t => ({ value: t, label: t, count: vulns.filter(v => v.tags.includes(t)).length }));

  const sevCounts   = SEV_OPTS.map(o => ({ ...o, count: vulns.filter(v => v.severity === o.value).length }));
  const statusCounts= STATUS_OPTS.map(o => ({ ...o, count: vulns.filter(v => v.status === o.value).length }));

  const filtered = vulns.filter(v => {
    const q = search.toLowerCase();
    const matchS  = !search || v.title.toLowerCase().includes(q) || v.target.toLowerCase().includes(q) || v.asset.toLowerCase().includes(q);
    const matchSev= sevFilter.length    === 0 || sevFilter.includes(v.severity);
    const matchSt = statusFilter.length === 0 || statusFilter.includes(v.status);
    const matchTag= tagFilter.length    === 0 || tagFilter.some(t => v.tags.includes(t));
    return matchS && matchSev && matchSt && matchTag;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged      = filtered.slice((page-1)*PAGE_SIZE, page*PAGE_SIZE);

  // Severity breakdown bars
  const totalVulns = vulns.length || 1;
  const sevBreakdown = SEV_OPTS.map(o => ({
    ...o,
    count: vulns.filter(v => v.severity === o.value).length,
    color: SEV[o.value]?.color || T.text3,
    bg:    SEV[o.value]?.bg    || T.bg3,
  }));

  const handleDismiss = async () => {
    if (!dismiss) return;
    try {
      await apiFetch(`/tenants/${tenantId}/findings/${dismiss.finding.id}`, {
        method: "PATCH",
        body: { status: "closed", comment: dismiss.comment },
      });
      toast.success("Vulnerability geschlossen");
      setDismiss(null);
      if (reload) reload();
    } catch (e) {
      toast.error("Fehler", { description: e.message });
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Header */}
      <div>
        <div style={{ fontFamily: T.fontSans, fontSize: 18, fontWeight: 700, color: T.text0, marginBottom: 4 }}>
          Vulnerabilities
        </div>
        <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>
          {vulns.length} gesamt · {filtered.length} gefiltert
        </div>
      </div>

      {/* Severity breakdown */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
        {sevBreakdown.map(s => (
          <div key={s.value} style={{
            background: T.bg2, border: `1px solid ${T.border}`,
            borderRadius: 8, padding: "14px 16px",
            cursor: "pointer",
            borderTop: `2px solid ${alpha(s.color, 60)}`,
            transition: "border-color 0.15s",
          }} onClick={() => setSevFilter(f => f.includes(s.value) ? f.filter(v => v !== s.value) : [...f, s.value])}>
            <div style={{ fontFamily: T.font, fontSize: 22, fontWeight: 700, color: s.color, marginBottom: 4 }}>
              {s.count}
            </div>
            <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text2 }}>{s.label}</div>
            <div style={{ marginTop: 8, height: 3, background: T.bg4, borderRadius: 2, overflow: "hidden" }}>
              <div style={{
                width: `${(s.count / totalVulns) * 100}%`,
                height: "100%", background: s.color, borderRadius: 2,
              }} />
            </div>
          </div>
        ))}
      </div>

      <Card>
        {/* Filter bar */}
        <div style={{
          display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center",
          padding: "12px 16px", borderBottom: `1px solid ${T.border}`,
        }}>
          <SearchInput value={search} onChange={v => { setSearch(v); setPage(1); }} placeholder="Titel, Target, Asset…" width={220} />
          <div style={{ width: 1, height: 20, background: T.border }} />
          <FacetedFilter label="Severity" options={sevCounts}    value={sevFilter}    onChange={v => { setSevFilter(v);    setPage(1); }} />
          <FacetedFilter label="Status"   options={statusCounts} value={statusFilter} onChange={v => { setStatusFilter(v); setPage(1); }} />
          {tagOpts.length > 0 && (
            <FacetedFilter label="Tags" options={tagOpts} value={tagFilter} onChange={v => { setTagFilter(v); setPage(1); }} />
          )}
          <span style={{ marginLeft: "auto", fontFamily: T.font, fontSize: 10, color: T.text3 }}>
            {filtered.length} Ergebnisse
          </span>
        </div>

        {/* Table */}
        {paged.length === 0 ? (
          <EmptyState icon={ShieldAlert} title="Keine Vulnerabilities" sub="Kein Ergebnis für diesen Filter oder noch kein Scan durchgeführt." />
        ) : (
          <>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    <TH>Titel</TH>
                    <TH>Severity</TH>
                    <TH>Target</TH>
                    <TH>Asset</TH>
                    <TH>Status</TH>
                    <TH>Datum</TH>
                    <TH>Aktionen</TH>
                  </tr>
                </thead>
                <tbody>
                  {paged.map(v => (
                    <tr key={v.id} style={{ transition: "background 0.1s" }}
                      onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      <TD style={{ maxWidth: 280 }}>
                        <div style={{
                          fontFamily: T.fontSans, fontSize: 12, color: T.text0, fontWeight: 500,
                          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                        }}>{v.title}</div>
                        {v.tags.length > 0 && (
                          <div style={{ display: "flex", gap: 4, marginTop: 4, flexWrap: "wrap" }}>
                            {v.tags.slice(0, 3).map(t => (
                              <span key={t} style={{
                                fontFamily: T.font, fontSize: 8, color: T.text3,
                                background: T.bg4, border: `1px solid ${T.border}`,
                                padding: "0 5px", borderRadius: 2,
                              }}>{t}</span>
                            ))}
                          </div>
                        )}
                      </TD>
                      <TD><SevBadge sev={v.severity} /></TD>
                      <TD style={{ fontFamily: T.font, fontSize: 11, color: T.text2 }}>{v.target}</TD>
                      <TD style={{ fontFamily: T.font, fontSize: 11, color: T.accent }}>{v.asset}</TD>
                      <TD><VulnStatusBadge status={v.status} /></TD>
                      <TD style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3 }}>
                        {v.date ? new Date(v.date).toLocaleDateString("de-DE") : "—"}
                      </TD>
                      <TD>
                        {v.status === "open" && (
                          <button
                            onClick={() => setDismiss({ finding: v, comment: "" })}
                            style={{
                              display: "flex", alignItems: "center", gap: 4,
                              background: "transparent", border: `1px solid ${T.border}`,
                              borderRadius: 4, padding: "3px 8px", fontFamily: T.font,
                              fontSize: 9, color: T.text2, cursor: "pointer",
                            }}
                          >
                            <X size={9} />Dismiss
                          </button>
                        )}
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

      {/* Dismiss dialog */}
      {dismiss && (
        <div style={{
          position: "fixed", inset: 0, zIndex: 300,
          background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center",
        }} onClick={() => setDismiss(null)}>
          <div onClick={e => e.stopPropagation()} style={{
            background: T.bg2, border: `1px solid ${T.border}`,
            borderRadius: 10, padding: 24, width: 420, boxShadow: "0 20px 60px rgba(0,0,0,0.5)",
          }}>
            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 12 }}>
              <div>
                <div style={{ fontFamily: T.fontSans, fontSize: 14, fontWeight: 700, color: T.text0, marginBottom: 4 }}>
                  Vulnerability schließen
                </div>
                <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text2 }}>
                  {dismiss.finding.title}
                </div>
              </div>
              <button onClick={() => setDismiss(null)} style={{
                background: "none", border: "none", color: T.text3, cursor: "pointer", flexShrink: 0,
              }}><X size={16} /></button>
            </div>

            <SevBadge sev={dismiss.finding.severity} style={{ marginBottom: 16 }} />

            <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text2, marginBottom: 6, marginTop: 16 }}>
              Kommentar (optional)
            </div>
            <textarea
              autoFocus
              value={dismiss.comment}
              onChange={e => setDismiss(d => ({ ...d, comment: e.target.value }))}
              placeholder="Begründung, Ticket-Nummer, Maßnahmen…"
              rows={4}
              style={{
                width: "100%", boxSizing: "border-box",
                padding: "9px 12px", background: T.bg3, border: `1px solid ${T.border}`,
                borderRadius: 6, fontFamily: T.font, fontSize: 11, color: T.text0,
                outline: "none", resize: "vertical", lineHeight: 1.6,
              }}
            />

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 16 }}>
              <Btn onClick={() => setDismiss(null)} variant="ghost">Abbrechen</Btn>
              <Btn onClick={handleDismiss} variant="primary">Schließen</Btn>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function VulnStatusBadge({ status }) {
  const styles = {
    open:     { color: T.critical, bg: T.criticalBg, border: T.criticalBorder },
    closed:   { color: T.accent,   bg: T.accent3,    border: T.accent         },
    accepted: { color: T.medium,   bg: T.mediumBg,   border: T.mediumBorder   },
    fp:       { color: T.text3,    bg: T.bg4,         border: T.border         },
  };
  const s = styles[status] || styles.open;
  const labels = { open: "Offen", closed: "Geschlossen", accepted: "Akzeptiert", fp: "False Positive" };
  return (
    <span style={{
      fontFamily: T.font, fontSize: 9, fontWeight: 700, color: s.color,
      background: s.bg, border: `1px solid ${s.border}`,
      padding: "1px 7px", borderRadius: 3,
    }}>{labels[status] || status}</span>
  );
}
