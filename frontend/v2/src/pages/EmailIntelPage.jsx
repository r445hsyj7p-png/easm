import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { Mail, Search, RefreshCw, Trash2, ChevronDown, ChevronUp, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { T, alpha } from "../theme";
import { apiFetch } from "../api/client";
import { useApp } from "../context/AppContext";
import { EmailRiskBadge, BAND_COLORS } from "../components/email/EmailRiskBadge";
import { ProviderTable } from "../components/email/ProviderTable";
import { EmailGraph } from "../components/email/EmailGraph";

const SEVERITY_COLORS = {
  CRITICAL: "var(--critical)",
  HIGH:     "var(--high)",
  MEDIUM:   "var(--medium)",
  LOW:      T.accent,
  INFO:     T.text3,
};

function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);
  const color = SEVERITY_COLORS[finding.severity] ?? T.text3;
  return (
    <div style={{
      border: `1px solid ${T.border}`,
      borderLeft: `3px solid ${color}`,
      borderRadius: 6,
      marginBottom: 6,
      background: T.bg2,
      overflow: "hidden",
    }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: "flex", alignItems: "center", gap: 10,
          width: "100%", padding: "10px 14px",
          background: "transparent", border: "none", cursor: "pointer",
          textAlign: "left",
        }}
      >
        <span style={{
          fontFamily: T.font, fontSize: 9, fontWeight: 700,
          color, background: alpha(color, 10),
          border: `1px solid ${alpha(color, 22)}`,
          padding: "1px 7px", borderRadius: 3, flexShrink: 0,
          textTransform: "uppercase",
        }}>
          {finding.severity}
        </span>
        <span style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text1, flex: 1 }}>
          {finding.title}
        </span>
        {open ? <ChevronUp size={13} color={T.text4} /> : <ChevronDown size={13} color={T.text4} />}
      </button>

      {open && (
        <div style={{ padding: "0 14px 12px", borderTop: `1px solid ${T.border}` }}>
          <p style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text2, margin: "10px 0 6px" }}>
            {finding.detail}
          </p>
          <div style={{
            background: alpha(T.accent, 6), border: `1px solid ${alpha(T.accent, 15)}`,
            borderRadius: 4, padding: "8px 10px",
          }}>
            <span style={{ fontFamily: T.fontSans, fontSize: 10, fontWeight: 600, color: T.accent }}>
              Empfehlung:&nbsp;
            </span>
            <span style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text2 }}>
              {finding.remediation}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

function SummaryCard({ label, value, sub }) {
  return (
    <div style={{
      background: T.bg2, border: `1px solid ${T.border}`,
      borderRadius: 8, padding: "12px 16px", flex: 1, minWidth: 100,
    }}>
      <div style={{ fontFamily: T.font, fontSize: 20, fontWeight: 700, color: T.text0 }}>{value}</div>
      <div style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text3, marginTop: 2 }}>{label}</div>
      {sub && <div style={{ fontFamily: T.font, fontSize: 9, color: T.text4, marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function DomainRow({ item, onSelect, onDelete, isActive }) {
  const color = (BAND_COLORS[item.risk_band] ?? { fg: T.text4 }).fg;
  return (
    <div
      onClick={() => onSelect(item)}
      style={{
        display: "flex", alignItems: "center", gap: 12,
        padding: "10px 14px",
        background: isActive ? alpha(T.accent, 6) : "transparent",
        borderLeft: `2px solid ${isActive ? T.accent : "transparent"}`,
        cursor: "pointer",
        transition: "all 0.1s",
      }}
      onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = T.bg3; }}
      onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = "transparent"; }}
    >
      <Mail size={13} color={T.text3} style={{ flexShrink: 0 }} />
      <span style={{ fontFamily: T.font, fontSize: 11, color: T.text1, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {item.domain}
      </span>
      {item.risk_score != null && (
        <span style={{
          fontFamily: T.font, fontSize: 10, fontWeight: 700,
          color, background: alpha(color, 10),
          border: `1px solid ${alpha(color, 20)}`,
          padding: "1px 7px", borderRadius: 3,
        }}>
          {item.risk_score}
        </span>
      )}
      {item.status === "running" || item.status === "pending" ? (
        <RefreshCw size={11} color={T.text4} style={{ animation: "spin 1s linear infinite" }} />
      ) : null}
      <button
        onClick={e => { e.stopPropagation(); onDelete(item.domain); }}
        style={{
          background: "none", border: "none", cursor: "pointer",
          color: T.text4, padding: 2, display: "flex",
        }}
        onMouseEnter={e => { e.currentTarget.style.color = "var(--critical)"; }}
        onMouseLeave={e => { e.currentTarget.style.color = T.text4; }}
      >
        <Trash2 size={11} />
      </button>
    </div>
  );
}

export default function EmailIntelPage() {
  const { tenantId } = useApp();
  const [domain, setDomain] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [domains, setDomains] = useState([]);
  const [activeResult, setActiveResult] = useState(null);
  const [polling, setPolling] = useState(null);   // job_id being polled
  const pollRef = useRef(null);

  const base = `/tenants/${tenantId}/email-intel`;

  // Load domain list on mount
  const loadDomains = useCallback(async () => {
    try {
      const data = await apiFetch(`${base}/domains`);
      setDomains(Array.isArray(data) ? data : []);
    } catch { /* silent */ }
  }, [base]);

  useEffect(() => { loadDomains(); }, [loadDomains]);

  // Poll for job completion
  useEffect(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    if (!polling) return;
    pollRef.current = setInterval(async () => {
      try {
        const result = await apiFetch(`${base}/result/${polling}`);
        const done = result.status === "complete" || result.status === "failed";
        setActiveResult(prev => {
          if (!done && prev?.status === result.status) return prev;
          return result;
        });
        if (done) {
          setPolling(null);
          setAnalyzing(false);
          loadDomains();
          if (result.status === "complete") {
            toast.success(`Analyse abgeschlossen: ${result.domain}`, {
              description: `Score ${result.risk_score} · ${result.risk_band}`,
            });
          } else {
            toast.error("Analyse fehlgeschlagen", { description: result.error });
          }
        }
      } catch { /* silent */ }
    }, 2500);
    return () => { clearInterval(pollRef.current); pollRef.current = null; };
  }, [polling, base, loadDomains]);

  const handleAnalyze = async () => {
    const d = domain.trim();
    if (!d) return;
    setAnalyzing(true);
    try {
      const resp = await apiFetch(`${base}/analyze`, { method: "POST", body: { domain: d } });
      setPolling(resp.job_id);
      setActiveResult({ job_id: resp.job_id, domain: d, status: "pending", findings: [], mx_records: [] });
      toast.success(`Analyse gestartet: ${d}`);
    } catch (e) {
      setAnalyzing(false);
      toast.error("Analyse-Start fehlgeschlagen", { description: e.message });
    }
  };

  const handleSelectDomain = async (item) => {
    try {
      const result = await apiFetch(`${base}/result/${item.job_id}`);
      setActiveResult(result);
    } catch (e) {
      toast.error("Ergebnis nicht ladbar", { description: e.message });
    }
  };

  const handleDelete = async (domainName) => {
    try {
      await apiFetch(`${base}/domains/${encodeURIComponent(domainName)}`, { method: "DELETE" });
      setDomains(prev => prev.filter(d => d.domain !== domainName));
      if (activeResult?.domain === domainName) setActiveResult(null);
      toast.success(`${domainName} gelöscht`);
    } catch (e) {
      toast.error("Löschen fehlgeschlagen", { description: e.message });
    }
  };

  const isRunning = activeResult?.status === "running" || activeResult?.status === "pending";
  const enrichedIps = useMemo(
    () => activeResult?.mx_records?.flatMap(mx => mx.ips || []) ?? [],
    [activeResult?.mx_records],
  );

  return (
    <div style={{ display: "flex", gap: 20, height: "calc(100vh - 80px)", overflow: "hidden" }}>
      {/* ── Left sidebar: domain list ────────────────────────────────────── */}
      <aside style={{
        width: 240, flexShrink: 0, display: "flex", flexDirection: "column",
        background: T.bg1, border: `1px solid ${T.border}`, borderRadius: 10, overflow: "hidden",
      }}>
        {/* Domain input */}
        <div style={{ padding: 12, borderBottom: `1px solid ${T.border}` }}>
          <div style={{ display: "flex", gap: 6 }}>
            <input
              value={domain}
              onChange={e => setDomain(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleAnalyze()}
              placeholder="example.com"
              style={{
                flex: 1, background: T.bg3, border: `1px solid ${T.border}`,
                borderRadius: 5, padding: "6px 8px",
                fontFamily: T.font, fontSize: 11, color: T.text1,
                outline: "none",
              }}
            />
            <button
              onClick={handleAnalyze}
              disabled={analyzing || !domain.trim()}
              style={{
                background: T.accent, border: "none", borderRadius: 5,
                padding: "6px 10px", cursor: analyzing ? "not-allowed" : "pointer",
                opacity: analyzing ? 0.6 : 1,
                display: "flex", alignItems: "center",
              }}
            >
              {analyzing
                ? <RefreshCw size={12} color="var(--background)" style={{ animation: "spin 1s linear infinite" }} />
                : <Search size={12} color="var(--background)" />
              }
            </button>
          </div>
        </div>

        {/* Domain list */}
        <div style={{ flex: 1, overflowY: "auto" }}>
          {domains.length === 0 && (
            <div style={{ padding: 16, fontFamily: T.fontSans, fontSize: 11, color: T.text4, textAlign: "center" }}>
              Noch keine Analysen.<br />Domain eingeben und Enter.
            </div>
          )}
          {domains.map(item => (
            <DomainRow
              key={item.job_id}
              item={item}
              onSelect={handleSelectDomain}
              onDelete={handleDelete}
              isActive={activeResult?.domain === item.domain}
            />
          ))}
        </div>
      </aside>

      {/* ── Main content ──────────────────────────────────────────────────── */}
      <main style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: 16 }}>
        {!activeResult && (
          <div style={{
            flex: 1, display: "flex", flexDirection: "column",
            alignItems: "center", justifyContent: "center", gap: 12, color: T.text4,
          }}>
            <Mail size={40} color={T.text4} />
            <div style={{ fontFamily: T.fontSans, fontSize: 13, color: T.text3 }}>
              E-Mail Infrastruktur Analyse
            </div>
            <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text4, maxWidth: 400, textAlign: "center" }}>
              SPF · DMARC · MX · Provider-Erkennung · ASN-Mapping · Risikobewertung
            </div>
          </div>
        )}

        {activeResult && (
          <>
            {/* Header: domain + status */}
            <div style={{
              display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap",
              background: T.bg1, border: `1px solid ${T.border}`,
              borderRadius: 10, padding: "14px 20px",
            }}>
              <div>
                <div style={{ fontFamily: T.font, fontSize: 18, fontWeight: 700, color: T.text0 }}>
                  {activeResult.domain}
                </div>
                <div style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text4, marginTop: 2 }}>
                  {activeResult.status === "complete" && activeResult.completed_at
                    ? `Analysiert: ${new Date(activeResult.completed_at).toLocaleString("de-DE")}`
                    : isRunning ? "Analyse läuft…"
                    : activeResult.status === "failed" ? "Analyse fehlgeschlagen"
                    : "Ausstehend"}
                </div>
              </div>

              {isRunning && (
                <div style={{ display: "flex", alignItems: "center", gap: 6, color: T.text3 }}>
                  <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} />
                  <span style={{ fontFamily: T.fontSans, fontSize: 11 }}>DNS-Analyse läuft…</span>
                </div>
              )}

              {activeResult.status === "complete" && activeResult.risk_score != null && (
                <div style={{ marginLeft: "auto" }}>
                  <EmailRiskBadge score={activeResult.risk_score} band={activeResult.risk_band} />
                </div>
              )}

              {activeResult.status === "failed" && (
                <div style={{ display: "flex", alignItems: "center", gap: 6, color: "var(--critical)", marginLeft: "auto" }}>
                  <AlertTriangle size={14} />
                  <span style={{ fontFamily: T.fontSans, fontSize: 11 }}>{activeResult.error}</span>
                </div>
              )}
            </div>

            {/* Summary cards */}
            {activeResult.graph_summary && (
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <SummaryCard label="SPF-Tiefe" value={activeResult.graph_summary.spf_depth} sub="include-Ebenen" />
                <SummaryCard label="DNS-Lookups" value={`${activeResult.graph_summary.spf_lookup_count}/10`} sub="RFC 7208 Limit" />
                <SummaryCard label="Externe Provider" value={activeResult.graph_summary.provider_count} />
                <SummaryCard label="MX-Server" value={activeResult.graph_summary.mx_count} />
                <SummaryCard label="IPs" value={activeResult.graph_summary.ip_count} />
                <SummaryCard label="ASNs" value={activeResult.graph_summary.asn_count} />
              </div>
            )}

            {/* SPF + DMARC raw */}
            {(activeResult.spf_raw || activeResult.dmarc_raw) && (
              <div style={{
                background: T.bg1, border: `1px solid ${T.border}`,
                borderRadius: 10, padding: "14px 20px",
              }}>
                <div style={{ fontFamily: T.fontSans, fontSize: 11, fontWeight: 600, color: T.text3, marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                  DNS-Records
                </div>
                {activeResult.spf_raw && (
                  <div style={{ marginBottom: 8 }}>
                    <span style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text4 }}>SPF </span>
                    <code style={{ fontFamily: T.font, fontSize: 10, color: T.accent, wordBreak: "break-all" }}>
                      {activeResult.spf_raw}
                    </code>
                  </div>
                )}
                {activeResult.dmarc_raw && (
                  <div>
                    <span style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text4 }}>DMARC </span>
                    <code style={{ fontFamily: T.font, fontSize: 10, color: "#f59e0b", wordBreak: "break-all" }}>
                      {activeResult.dmarc_raw}
                    </code>
                  </div>
                )}
              </div>
            )}

            {/* Infrastructure graph */}
            {activeResult.graph_json && (
              <div style={{
                background: T.bg1, border: `1px solid ${T.border}`,
                borderRadius: 10, padding: "14px 20px",
              }}>
                <div style={{ fontFamily: T.fontSans, fontSize: 11, fontWeight: 600, color: T.text3, marginBottom: 12, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                  Infrastruktur-Graph
                </div>
                <EmailGraph graphData={activeResult.graph_json} />
              </div>
            )}

            {/* Findings */}
            {activeResult.findings?.length > 0 && (
              <div style={{
                background: T.bg1, border: `1px solid ${T.border}`,
                borderRadius: 10, padding: "14px 20px",
              }}>
                <div style={{ fontFamily: T.fontSans, fontSize: 11, fontWeight: 600, color: T.text3, marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                  Findings ({activeResult.findings.length})
                </div>
                {activeResult.findings
                  .sort((a, b) => {
                    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
                    return order.indexOf(a.severity) - order.indexOf(b.severity);
                  })
                  .map(f => <FindingCard key={f.code} finding={f} />)
                }
              </div>
            )}

            {/* Provider table */}
            {activeResult.mx_records?.length > 0 && (
              <div style={{
                background: T.bg1, border: `1px solid ${T.border}`,
                borderRadius: 10, padding: "14px 20px",
              }}>
                <div style={{ fontFamily: T.fontSans, fontSize: 11, fontWeight: 600, color: T.text3, marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                  MX-Server
                </div>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: `1px solid ${T.border}` }}>
                      {["Priorität", "FQDN", "IPs"].map(h => (
                        <th key={h} style={{ padding: "6px 12px", textAlign: "left", fontFamily: T.fontSans, fontSize: 10, color: T.text4, textTransform: "uppercase" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {activeResult.mx_records.map(mx => (
                      <tr key={mx.fqdn} style={{ borderBottom: `1px solid ${T.border}` }}>
                        <td style={{ padding: "8px 12px", fontFamily: T.font, fontSize: 11, color: T.text3 }}>{mx.priority}</td>
                        <td style={{ padding: "8px 12px", fontFamily: T.font, fontSize: 11, color: T.text1 }}>{mx.fqdn}</td>
                        <td style={{ padding: "8px 12px", fontFamily: T.font, fontSize: 10, color: T.text3 }}>
                          {(mx.ips || []).map(ip => ip.address).join(", ") || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </main>

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
