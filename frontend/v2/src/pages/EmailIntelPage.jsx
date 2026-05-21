import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { Mail, Search, RefreshCw, Trash2, ChevronDown, ChevronUp, AlertTriangle, Settings } from "lucide-react";
import { toast } from "sonner";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine,
} from "recharts";
import { T, alpha } from "../theme";
import { apiFetch } from "../api/client";
import { useApp } from "../context/AppContext";
import { EmailRiskBadge, BAND_COLORS } from "../components/email/EmailRiskBadge";
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

function SummaryCard({ label, value, sub, warn }) {
  const color = warn ? "var(--critical)" : T.text0;
  return (
    <div style={{
      background: T.bg2, border: `1px solid ${warn ? "rgba(220,38,38,0.25)" : T.border}`,
      borderRadius: 8, padding: "12px 16px", flex: 1, minWidth: 100,
    }}>
      <div style={{ fontFamily: T.font, fontSize: 20, fontWeight: 700, color }}>{value}</div>
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
      {(item.status === "running" || item.status === "pending") && (
        <RefreshCw size={11} color={T.text4} style={{ animation: "spin 1s linear infinite" }} />
      )}
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

function ScoreHistoryChart({ history }) {
  if (!history || history.length < 2) return null;
  const data = [...history].reverse(); // oldest → newest
  const fmt = (d) => new Date(d).toLocaleDateString("de-DE", { month: "short", day: "numeric" });
  const fmtFull = (d) => new Date(d).toLocaleString("de-DE");
  return (
    <div style={{
      background: T.bg1, border: `1px solid ${T.border}`,
      borderRadius: 10, padding: "14px 20px",
    }}>
      <div style={{ fontFamily: T.fontSans, fontSize: 11, fontWeight: 600, color: T.text3, marginBottom: 12, textTransform: "uppercase", letterSpacing: "0.05em" }}>
        Score-Verlauf ({history.length} Analysen)
      </div>
      <ResponsiveContainer width="100%" height={120}>
        <LineChart data={data} margin={{ top: 6, right: 12, bottom: 0, left: 0 }}>
          <XAxis
            dataKey="created_at"
            tickFormatter={fmt}
            tick={{ fontFamily: T.font, fontSize: 9, fill: T.text4 }}
            axisLine={false} tickLine={false}
          />
          <YAxis
            domain={[0, 100]}
            width={28}
            tick={{ fontFamily: T.font, fontSize: 9, fill: T.text4 }}
            axisLine={false} tickLine={false}
          />
          <Tooltip
            formatter={(v) => [v, "Risk-Score"]}
            labelFormatter={fmtFull}
            contentStyle={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, fontFamily: T.fontSans, fontSize: 11 }}
          />
          <ReferenceLine y={75} stroke="rgba(220,38,38,0.2)" strokeDasharray="3 3" />
          <ReferenceLine y={50} stroke="rgba(234,179,8,0.2)" strokeDasharray="3 3" />
          <Line
            type="monotone" dataKey="risk_score"
            stroke={T.accent} strokeWidth={2}
            dot={{ r: 3, fill: T.accent, strokeWidth: 0 }}
            activeDot={{ r: 5 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

const PAGE_SIZE = 30;

export default function EmailIntelPage() {
  const { tenantId } = useApp();
  const [domain, setDomain] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [domains, setDomains]   = useState([]);
  const [page, setPage]         = useState(0);
  const [activeResult, setActiveResult] = useState(null);
  const [polling, setPolling]   = useState(null);
  const [history, setHistory]   = useState([]);
  const [settings, setSettings] = useState({ auto_rescan_enabled: false, rescan_interval_days: 7 });
  const [showSettings, setShowSettings] = useState(false);
  const [savingSettings, setSavingSettings] = useState(false);
  const pollRef = useRef(null);

  const base = `/tenants/${tenantId}/email-intel`;

  const loadDomains = useCallback(async () => {
    try {
      const data = await apiFetch(`${base}/domains`);
      setDomains(Array.isArray(data) ? data : []);
      setPage(0);
    } catch { /* silent */ }
  }, [base]);

  const loadHistory = useCallback(async (domainName) => {
    try {
      const data = await apiFetch(`${base}/domains/${encodeURIComponent(domainName)}/history`);
      setHistory(Array.isArray(data) ? data : []);
    } catch { setHistory([]); }
  }, [base]);

  const loadSettings = useCallback(async () => {
    try {
      const data = await apiFetch(`${base}/settings`);
      setSettings(data);
    } catch { /* silent — table may not exist yet */ }
  }, [base]);

  useEffect(() => { loadDomains(); loadSettings(); }, [loadDomains, loadSettings]);

  // Load history when an active completed result changes domain
  useEffect(() => {
    if (activeResult?.status === "complete" && activeResult.domain) {
      loadHistory(activeResult.domain);
    } else {
      setHistory([]);
    }
  }, [activeResult?.domain, activeResult?.status, loadHistory]);

  // Poll for job completion
  useEffect(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    if (!polling) return;
    let mounted = true;
    pollRef.current = setInterval(async () => {
      try {
        const result = await apiFetch(`${base}/result/${polling}`);
        if (!mounted) return;
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
    return () => { mounted = false; clearInterval(pollRef.current); pollRef.current = null; };
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

  const handleSaveSettings = async () => {
    setSavingSettings(true);
    try {
      await apiFetch(`${base}/settings`, { method: "PUT", body: settings });
      toast.success("Re-Scan-Einstellungen gespeichert");
      setShowSettings(false);
    } catch (e) {
      toast.error("Speichern fehlgeschlagen", { description: e.message });
    } finally {
      setSavingSettings(false);
    }
  };

  const gs = useMemo(() => activeResult?.graph_summary, [activeResult?.graph_summary]);
  const isRunning = activeResult?.status === "running" || activeResult?.status === "pending";

  const getStatusText = () => {
    if (activeResult?.status === "complete" && activeResult.completed_at)
      return `Analysiert: ${new Date(activeResult.completed_at).toLocaleString("de-DE")}`;
    if (isRunning) return "Analyse läuft…";
    if (activeResult?.status === "failed") return "Analyse fehlgeschlagen";
    return "Ausstehend";
  };
  const totalPages = Math.ceil(domains.length / PAGE_SIZE);
  const pagedDomains = useMemo(
    () => domains.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE),
    [domains, page],
  );

  return (
    <div style={{ display: "flex", gap: 20, height: "calc(100vh - 80px)", overflow: "hidden" }}>
      {/* ── Left sidebar ─────────────────────────────────────────────────── */}
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
                fontFamily: T.font, fontSize: 11, color: T.text1, outline: "none",
              }}
            />
            <button
              onClick={handleAnalyze}
              disabled={analyzing || !domain.trim()}
              style={{
                background: T.accent, border: "none", borderRadius: 5,
                padding: "6px 10px", cursor: analyzing ? "not-allowed" : "pointer",
                opacity: analyzing ? 0.6 : 1, display: "flex", alignItems: "center",
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
          {pagedDomains.map(item => (
            <DomainRow
              key={item.job_id}
              item={item}
              onSelect={handleSelectDomain}
              onDelete={handleDelete}
              isActive={activeResult?.domain === item.domain}
            />
          ))}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "6px 10px", borderTop: `1px solid ${T.border}`,
            fontFamily: T.fontSans, fontSize: 10, color: T.text4, flexShrink: 0,
          }}>
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
              style={{ background: "none", border: "none", cursor: page === 0 ? "default" : "pointer", color: page === 0 ? T.text4 : T.text2, padding: "2px 6px" }}
            >‹</button>
            <span>{page + 1} / {totalPages}</span>
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
              style={{ background: "none", border: "none", cursor: page >= totalPages - 1 ? "default" : "pointer", color: page >= totalPages - 1 ? T.text4 : T.text2, padding: "2px 6px" }}
            >›</button>
          </div>
        )}

        {/* Auto Re-Scan Settings */}
        <div style={{ borderTop: `1px solid ${T.border}`, flexShrink: 0 }}>
          <button
            onClick={() => setShowSettings(s => !s)}
            style={{
              display: "flex", alignItems: "center", gap: 7, width: "100%",
              padding: "8px 12px", background: "transparent", border: "none",
              cursor: "pointer", color: T.text3,
            }}
          >
            <Settings size={11} />
            <span style={{ fontFamily: T.fontSans, fontSize: 10, flex: 1, textAlign: "left" }}>
              Auto Re-Scan
            </span>
            {settings.auto_rescan_enabled && (
              <span style={{
                fontFamily: T.font, fontSize: 8, color: T.accent,
                background: alpha(T.accent, 12), border: `1px solid ${alpha(T.accent, 25)}`,
                padding: "1px 5px", borderRadius: 3,
              }}>AN</span>
            )}
            {showSettings ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
          </button>

          {showSettings && (
            <div style={{ padding: "0 12px 12px", display: "flex", flexDirection: "column", gap: 8 }}>
              <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={settings.auto_rescan_enabled}
                  onChange={e => setSettings(s => ({ ...s, auto_rescan_enabled: e.target.checked }))}
                  style={{ accentColor: T.accent }}
                />
                <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text2 }}>
                  Automatisch wiederholen
                </span>
              </label>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text4, flex: 1 }}>Intervall (Tage)</span>
                <input
                  type="number" min={1} max={90}
                  value={settings.rescan_interval_days}
                  onChange={e => setSettings(s => ({ ...s, rescan_interval_days: Math.max(1, Math.min(90, parseInt(e.target.value) || 7)) }))}
                  style={{
                    width: 52, background: T.bg3, border: `1px solid ${T.border}`,
                    borderRadius: 4, padding: "3px 6px",
                    fontFamily: T.font, fontSize: 11, color: T.text1,
                    textAlign: "right",
                  }}
                />
              </div>
              <button
                onClick={handleSaveSettings} disabled={savingSettings}
                style={{
                  background: T.accent, border: "none", borderRadius: 5,
                  padding: "5px 10px", cursor: savingSettings ? "not-allowed" : "pointer",
                  opacity: savingSettings ? 0.6 : 1,
                  fontFamily: T.fontSans, fontSize: 10, color: "var(--background)",
                }}
              >
                {savingSettings ? "Speichert…" : "Speichern"}
              </button>
            </div>
          )}
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
              SPF · DMARC · MX · DKIM · RBL · MTA-STS · Provider-Erkennung · ASN-Mapping
            </div>
          </div>
        )}

        {activeResult && (
          <>
            {/* Header */}
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
                  {getStatusText()}
                </div>
              </div>

              {isRunning && (
                <div style={{ display: "flex", alignItems: "center", gap: 6, color: T.text3 }}>
                  <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} />
                  <span style={{ fontFamily: T.fontSans, fontSize: 11 }}>DNS-Analyse läuft…</span>
                </div>
              )}

              {activeResult.status === "failed" && activeResult.error && (
                <div style={{
                  display: "flex", alignItems: "flex-start", gap: 8, marginLeft: "auto",
                  background: "rgba(var(--critical-rgb,220,38,38),0.08)",
                  border: "1px solid rgba(var(--critical-rgb,220,38,38),0.25)",
                  borderRadius: 6, padding: "8px 12px", maxWidth: 420,
                }}>
                  <AlertTriangle size={13} color="var(--critical)" style={{ flexShrink: 0, marginTop: 1 }} />
                  <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1, wordBreak: "break-word" }}>
                    {activeResult.error}
                  </span>
                </div>
              )}

              {activeResult.status === "complete" && activeResult.risk_score != null && (
                <div style={{ marginLeft: "auto" }}>
                  <EmailRiskBadge score={activeResult.risk_score} band={activeResult.risk_band} />
                </div>
              )}
            </div>

            {/* Summary cards */}
            {gs && (
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <SummaryCard label="SPF-Tiefe" value={gs.spf_depth} sub="include-Ebenen" />
                <SummaryCard label="DNS-Lookups" value={`${gs.spf_lookup_count}/10`} sub="RFC 7208" warn={gs.spf_lookup_count > 10} />
                <SummaryCard label="Provider" value={gs.provider_count} />
                <SummaryCard label="MX-Server" value={gs.mx_count} />
                <SummaryCard label="IPs" value={gs.ip_count} />
                <SummaryCard label="ASNs" value={gs.asn_count} />
                <SummaryCard
                  label="DKIM"
                  value={gs.dkim_selectors_found > 0 ? `${gs.dkim_selectors_found} Sel.` : "—"}
                  sub={gs.dkim_weak_keys > 0 ? `${gs.dkim_weak_keys} schwach` : gs.dkim_selectors_found > 0 ? "OK" : "nicht gefunden"}
                  warn={gs.dkim_weak_keys > 0}
                />
                <SummaryCard
                  label="RBL"
                  value={gs.rbl_listed_count > 0 ? gs.rbl_listed_count : "✓"}
                  sub={gs.rbl_listed_count > 0 ? "gelistet" : "sauber"}
                  warn={gs.rbl_listed_count > 0}
                />
                <SummaryCard
                  label="MTA-STS"
                  value={gs.mta_sts_mode ?? "—"}
                  sub={gs.tls_rpt_present ? "TLS-RPT ✓" : "kein TLS-RPT"}
                  warn={!gs.mta_sts_mode}
                />
              </div>
            )}

            {/* Score history chart */}
            <ScoreHistoryChart history={history} />

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
                {[...activeResult.findings]
                  .sort((a, b) => {
                    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
                    return order.indexOf(a.severity) - order.indexOf(b.severity);
                  })
                  .map(f => <FindingCard key={f.code} finding={f} />)
                }
              </div>
            )}

            {/* MX table */}
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
