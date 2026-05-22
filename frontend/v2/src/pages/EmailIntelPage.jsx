import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { Mail, Search, RefreshCw, Trash2, ChevronDown, ChevronUp, AlertTriangle, Settings, List } from "lucide-react";
import { toast } from "sonner";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine,
} from "recharts";
import { T, alpha } from "../theme";
import { apiFetch } from "../api/client";
import { useApp } from "../context/AppContext";
import { EmailRiskBadge, BAND_COLORS } from "../components/email/EmailRiskBadge";
import { EmailGraph } from "../components/email/EmailGraph";

function ScoreDeltaBadge({ delta }) {
  if (delta == null) return null;
  const abs = Math.abs(delta);
  if (abs < 5) return null;
  const up = delta > 0;
  // ≥5 neutral grey, ≥10 coloured
  const strong = abs >= 10;
  const color = strong ? (up ? "var(--critical)" : "var(--success, #22c55e)") : T.text3;
  const bg    = strong ? (up ? "rgba(220,38,38,0.1)" : "rgba(34,197,94,0.1)") : alpha(T.text3, 8);
  const border= strong ? (up ? "rgba(220,38,38,0.3)" : "rgba(34,197,94,0.3)") : alpha(T.text3, 20);
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 4,
      padding: "3px 10px", borderRadius: 6,
      background: bg, border: `1px solid ${border}`,
      fontFamily: T.font, fontSize: 12, fontWeight: 700, color,
      flexShrink: 0,
    }}>
      {up ? "▲" : "▼"} {up ? "+" : ""}{delta}
    </div>
  );
}

const CHIP_THEMES = {
  ok:      { border: "#22c55e", icon: "✓", color: "#22c55e",         bg: "rgba(34,197,94,0.05)" },
  error:   { border: "var(--critical)", icon: "✗", color: "var(--critical)", bg: "rgba(220,38,38,0.05)" },
  warning: { border: "#f59e0b", icon: "⚠", color: "#f59e0b",        bg: "rgba(245,158,11,0.05)" },
  info:    { border: T.text3,   icon: "ⓘ", color: T.text3,           bg: T.bg2 },
  neutral: { border: T.border,  icon: "—", color: T.text4,           bg: T.bg2 },
};

function ConsistencyChip({ label, status, text }) {
  const theme = CHIP_THEMES[status] ?? CHIP_THEMES.neutral;
  return (
    <div style={{
      display: "flex", alignItems: "flex-start", gap: 8,
      padding: "8px 12px", borderRadius: 6, flex: 1, minWidth: 130,
      background: theme.bg,
      borderLeft: `3px solid ${theme.border}`,
      border: `1px solid ${alpha(theme.border === T.border ? T.text4 : theme.border, 20)}`,
      borderLeftWidth: 3,
    }}>
      <span style={{ fontFamily: T.font, fontSize: 12, color: theme.color, flexShrink: 0, marginTop: 1 }}>
        {theme.icon}
      </span>
      <div>
        <div style={{ fontFamily: T.font, fontSize: 10, fontWeight: 700, color: T.text2 }}>{label}</div>
        <div style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text3, marginTop: 2 }}>{text}</div>
      </div>
    </div>
  );
}

function ConsistencyChecks({ findings, gs }) {
  const hasFind = (code) => findings?.some(f => f.code === code);

  const spfMxOk = !hasFind("MX_NOT_IN_SPF");
  const mtaStsMxOk = !hasFind("MTA_STS_MX_NOT_COVERED");
  const dkimOk = !hasFind("DKIM_MISSING_FOR_PROVIDER");
  const ruaExternal = hasFind("DMARC_EXTERNAL_REPORTING");
  const mtaConfigured = !!gs?.mta_sts_mode;

  const missingProviders = gs?.dkim_missing_providers ?? [];
  const ruaDomains = gs?.rua_external_domains ?? [];

  return (
    <div style={{
      background: T.bg1, border: `1px solid ${T.border}`,
      borderRadius: 10, padding: "14px 20px",
    }}>
      <div style={{ fontFamily: T.fontSans, fontSize: 11, fontWeight: 600, color: T.text3, marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.05em" }}>
        Konsistenz-Prüfungen
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <ConsistencyChip
          label="SPF↔MX"
          status={spfMxOk ? "ok" : "error"}
          text={spfMxOk ? "alle MX-IPs in SPF" : "MX-IPs nicht autorisiert"}
        />
        <ConsistencyChip
          label="MTA-STS↔MX"
          status={!mtaConfigured ? "neutral" : mtaStsMxOk ? "ok" : "warning"}
          text={!mtaConfigured ? "nicht konfiguriert" : mtaStsMxOk ? "Policy aktuell" : "MX-Server fehlen in Policy"}
        />
        <ConsistencyChip
          label="Provider DKIM"
          status={dkimOk ? "ok" : "warning"}
          text={dkimOk
            ? "alle Provider konfiguriert"
            : missingProviders.length > 0
              ? `${missingProviders[0]}${missingProviders.length > 1 ? ` +${missingProviders.length - 1}` : ""} fehlt`
              : "DKIM-Selector fehlt"}
        />
        <ConsistencyChip
          label="rua= Empfänger"
          status={ruaExternal ? "info" : "ok"}
          text={ruaExternal
            ? ruaDomains.slice(0, 2).join(", ") + (ruaDomains.length > 2 ? " …" : "") + " (extern)"
            : "intern / nicht gesetzt"}
        />
      </div>
    </div>
  );
}

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
  const [pollError, setPollError]   = useState(null);
  const [pollStartedAt, setPollStartedAt] = useState(null);
  const [history, setHistory]   = useState([]);
  const [settings, setSettings] = useState({ auto_rescan_enabled: false, rescan_interval_days: 7 });
  const [showSettings, setShowSettings] = useState(false);
  const [savingSettings, setSavingSettings] = useState(false);
  const [bulkMode, setBulkMode] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const [analyzeError, setAnalyzeError] = useState(null);
  const [bulkAnalyzing, setBulkAnalyzing] = useState(false);
  const [bulkResults, setBulkResults] = useState([]);
  const [now, setNow] = useState(Date.now());
  const pollRef = useRef(null);

  // Tick every 5 s while polling so timeout banner appears without extra state
  useEffect(() => {
    if (!polling) return;
    const t = setInterval(() => setNow(Date.now()), 5000);
    return () => clearInterval(t);
  }, [polling]);

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
    let consecutiveErrors = 0;
    setPollError(null);
    setPollStartedAt(Date.now());
    pollRef.current = setInterval(async () => {
      try {
        const result = await apiFetch(`${base}/result/${polling}`);
        if (!mounted) return;
        consecutiveErrors = 0;
        setPollError(null);
        const done = result.status === "complete" || result.status === "failed";
        setActiveResult(prev => {
          if (!done && prev?.status === result.status) return prev;
          return result;
        });
        if (done) {
          setPolling(null);
          setAnalyzing(false);
          setPollStartedAt(null);
          loadDomains();
          if (result.status === "complete") {
            toast.success(`Analyse abgeschlossen: ${result.domain}`, {
              description: `Score ${result.risk_score} · ${result.risk_band}`,
            });
          }
        }
      } catch (e) {
        if (!mounted) return;
        consecutiveErrors++;
        if (consecutiveErrors >= 3) {
          setPollError(e.message);
        }
      }
    }, 2500);
    return () => { mounted = false; clearInterval(pollRef.current); pollRef.current = null; };
  }, [polling, base, loadDomains]);

  const handleAnalyze = async () => {
    const d = domain.trim();
    if (!d) return;
    setAnalyzing(true);
    setAnalyzeError(null);
    setPollError(null);
    setPollStartedAt(null);
    try {
      const resp = await apiFetch(`${base}/analyze`, { method: "POST", body: { domain: d } });
      setPolling(resp.job_id);
      setActiveResult({ job_id: resp.job_id, domain: d, status: "pending", findings: [], mx_records: [] });
      toast.success(`Analyse gestartet: ${d}`);
    } catch (e) {
      setAnalyzing(false);
      setAnalyzeError(e.message);
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

  const handleBulkAnalyze = async () => {
    const parsedDomains = [...new Set(
      bulkText.split(/[\n,]+/).map(d => d.trim()).filter(Boolean)
    )].slice(0, 20);
    if (parsedDomains.length === 0) return;
    setBulkAnalyzing(true);
    setBulkResults([]);
    setAnalyzeError(null);
    try {
      const resp = await apiFetch(`${base}/analyze/bulk`, { method: "POST", body: { domains: parsedDomains } });
      setBulkResults(resp.results || []);
      const queued = (resp.results || []).filter(r => r.status === "pending" || r.status === "running").length;
      toast.success(`Bulk-Analyse: ${queued} Domain(s) gestartet`);
      setBulkText("");
      await loadDomains();
    } catch (e) {
      setAnalyzeError(e.message);
    } finally {
      setBulkAnalyzing(false);
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
          {/* Mode toggle */}
          <div style={{ display: "flex", gap: 4, marginBottom: 8 }}>
            <button
              onClick={() => { setBulkMode(false); setBulkResults([]); }}
              style={{
                flex: 1, padding: "3px 0", border: `1px solid ${T.border}`,
                borderRadius: 4, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 4,
                background: !bulkMode ? alpha(T.accent, 12) : T.bg3,
                color: !bulkMode ? T.accent : T.text4,
                fontFamily: T.fontSans, fontSize: 10,
              }}
            >
              <Search size={10} /> Einzeln
            </button>
            <button
              onClick={() => { setBulkMode(true); setBulkResults([]); }}
              style={{
                flex: 1, padding: "3px 0", border: `1px solid ${T.border}`,
                borderRadius: 4, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 4,
                background: bulkMode ? alpha(T.accent, 12) : T.bg3,
                color: bulkMode ? T.accent : T.text4,
                fontFamily: T.fontSans, fontSize: 10,
              }}
            >
              <List size={10} /> Bulk
            </button>
          </div>

          {!bulkMode ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <div style={{ display: "flex", gap: 6 }}>
                <input
                  value={domain}
                  onChange={e => { setDomain(e.target.value); if (analyzeError) setAnalyzeError(null); }}
                  onKeyDown={e => e.key === "Enter" && handleAnalyze()}
                  placeholder="example.com"
                  style={{
                    flex: 1, background: T.bg3,
                    border: `1px solid ${analyzeError ? "var(--critical)" : T.border}`,
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
              {analyzeError && (
                <div style={{
                  background: "color-mix(in srgb, var(--critical) 10%, transparent)",
                  border: "1px solid color-mix(in srgb, var(--critical) 35%, transparent)",
                  borderRadius: 5, padding: "5px 8px",
                  display: "flex", alignItems: "flex-start", gap: 5,
                }}>
                  <AlertTriangle size={11} color="var(--critical)" style={{ flexShrink: 0, marginTop: 1 }} />
                  <span style={{ fontFamily: T.fontSans, fontSize: 10, color: "var(--critical)", lineHeight: 1.4 }}>
                    {analyzeError}
                  </span>
                </div>
              )}
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <textarea
                value={bulkText}
                onChange={e => setBulkText(e.target.value)}
                placeholder={"example.com\nother.org\n…"}
                rows={5}
                style={{
                  width: "100%", background: T.bg3, border: `1px solid ${T.border}`,
                  borderRadius: 5, padding: "6px 8px", resize: "vertical",
                  fontFamily: T.font, fontSize: 11, color: T.text1, outline: "none",
                  boxSizing: "border-box",
                }}
              />
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{ fontFamily: T.fontSans, fontSize: 9, color: T.text4 }}>
                  {Math.min([...new Set(bulkText.split(/[\n,]+/).map(d => d.trim()).filter(Boolean))].length, 20)}/20 Domains
                </span>
                <button
                  onClick={handleBulkAnalyze}
                  disabled={bulkAnalyzing || !bulkText.trim()}
                  style={{
                    background: T.accent, border: "none", borderRadius: 5,
                    padding: "5px 12px", cursor: bulkAnalyzing ? "not-allowed" : "pointer",
                    opacity: bulkAnalyzing ? 0.6 : 1,
                    fontFamily: T.fontSans, fontSize: 10, color: "var(--background)",
                    display: "flex", alignItems: "center", gap: 5,
                  }}
                >
                  {bulkAnalyzing
                    ? <RefreshCw size={10} color="var(--background)" style={{ animation: "spin 1s linear infinite" }} />
                    : <List size={10} color="var(--background)" />
                  }
                  Analysieren
                </button>
              </div>
              {analyzeError && bulkMode && (
                <div style={{
                  background: "color-mix(in srgb, var(--critical) 10%, transparent)",
                  border: "1px solid color-mix(in srgb, var(--critical) 35%, transparent)",
                  borderRadius: 5, padding: "5px 8px",
                  display: "flex", alignItems: "flex-start", gap: 5,
                }}>
                  <AlertTriangle size={11} color="var(--critical)" style={{ flexShrink: 0, marginTop: 1 }} />
                  <span style={{ fontFamily: T.fontSans, fontSize: 10, color: "var(--critical)", lineHeight: 1.4 }}>
                    {analyzeError}
                  </span>
                </div>
              )}
              {bulkResults.length > 0 && (
                <div style={{
                  marginTop: 4, maxHeight: 120, overflowY: "auto",
                  border: `1px solid ${T.border}`, borderRadius: 5,
                }}>
                  {bulkResults.map(r => {
                    const dotColor = r.status === "error" ? "var(--critical)"
                      : r.status === "complete" ? "var(--success, #22c55e)"
                      : r.status === "pending" || r.status === "running" ? T.accent
                      : T.text3;
                    const label = r.status === "error" ? "Fehler"
                      : r.status === "pending" ? "Gestartet"
                      : r.status === "running" ? "Läuft"
                      : r.status === "complete" ? "Fertig"
                      : r.status === "failed" ? "Fehler"
                      : r.status;
                    const domainItem = domains.find(d => d.domain === r.domain);
                    return (
                      <div
                        key={r.domain}
                        onClick={() => domainItem && handleSelectDomain(domainItem)}
                        style={{
                          display: "flex", alignItems: "center", gap: 6,
                          padding: "4px 8px", borderBottom: `1px solid ${T.border}`,
                          fontSize: 10, fontFamily: T.font,
                          cursor: domainItem ? "pointer" : "default",
                        }}
                        onMouseEnter={e => { if (domainItem) e.currentTarget.style.background = T.bg3; }}
                        onMouseLeave={e => { e.currentTarget.style.background = "transparent"; }}
                      >
                        <span style={{ width: 6, height: 6, borderRadius: "50%", flexShrink: 0, background: dotColor }} />
                        <span style={{ flex: 1, color: T.text2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {r.domain}
                        </span>
                        <span style={{ color: T.text4, flexShrink: 0 }}>{label}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
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
                  {activeResult.created_at && (
                    <span style={{ marginLeft: 8, opacity: 0.7 }}>
                      · gestartet {new Date(activeResult.created_at).toLocaleString("de-DE")}
                    </span>
                  )}
                </div>
              </div>

              {isRunning && !pollError && (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, color: T.text3 }}>
                    <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} />
                    <span style={{ fontFamily: T.fontSans, fontSize: 11 }}>DNS-Analyse läuft…</span>
                  </div>
                  {pollStartedAt && now - pollStartedAt > 90_000 && (
                    <div style={{
                      display: "flex", alignItems: "center", gap: 5,
                      background: "color-mix(in srgb, var(--warning,#f59e0b) 12%, transparent)",
                      border: "1px solid color-mix(in srgb, var(--warning,#f59e0b) 30%, transparent)",
                      borderRadius: 5, padding: "4px 8px",
                    }}>
                      <AlertTriangle size={11} color="var(--warning,#f59e0b)" />
                      <span style={{ fontFamily: T.fontSans, fontSize: 10, color: "var(--warning,#f59e0b)" }}>
                        Dauert länger als erwartet — läuft der Worker?
                      </span>
                    </div>
                  )}
                </div>
              )}

              {isRunning && pollError && (
                <div style={{
                  display: "flex", alignItems: "flex-start", gap: 8, marginLeft: "auto",
                  background: "color-mix(in srgb, var(--critical) 8%, transparent)",
                  border: "1px solid color-mix(in srgb, var(--critical) 25%, transparent)",
                  borderRadius: 6, padding: "8px 12px", maxWidth: 380,
                }}>
                  <AlertTriangle size={13} color="var(--critical)" style={{ flexShrink: 0, marginTop: 1 }} />
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1 }}>
                      Ergebnis nicht abrufbar: {pollError}
                    </span>
                    <button
                      onClick={() => { setPolling(null); setAnalyzing(false); setPollError(null); }}
                      style={{
                        alignSelf: "flex-start", background: "none", border: `1px solid ${T.border}`,
                        borderRadius: 4, padding: "2px 8px", cursor: "pointer",
                        fontFamily: T.fontSans, fontSize: 10, color: T.text3,
                      }}
                    >
                      Abbrechen
                    </button>
                  </div>
                </div>
              )}

              {(activeResult.status === "failed") && (
                <div style={{
                  display: "flex", alignItems: "flex-start", gap: 8, marginLeft: "auto",
                  background: "color-mix(in srgb, var(--critical) 8%, transparent)",
                  border: "1px solid color-mix(in srgb, var(--critical) 25%, transparent)",
                  borderRadius: 6, padding: "8px 12px", maxWidth: 420,
                }}>
                  <AlertTriangle size={13} color="var(--critical)" style={{ flexShrink: 0, marginTop: 1 }} />
                  <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text1, wordBreak: "break-word" }}>
                    {activeResult.error || "Analyse fehlgeschlagen"}
                  </span>
                </div>
              )}

              {activeResult.status === "complete" && activeResult.risk_score != null && (
                <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
                  <ScoreDeltaBadge delta={gs?.score_delta} />
                  <EmailRiskBadge score={activeResult.risk_score} band={activeResult.risk_band} />
                </div>
              )}
            </div>

            {/* Summary cards */}
            {gs && (
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <SummaryCard label="SPF-Tiefe" value={gs.spf_depth} sub="include-Ebenen" />
                <SummaryCard label="SPF-Includes" value={gs.spf_include_count} sub="verschachtelt" />
                <SummaryCard label="DNS-Lookups" value={`${gs.spf_lookup_count}/10`} sub="RFC 7208" warn={gs.spf_lookup_count > 10} />
                <SummaryCard label="Provider" value={gs.provider_count} />
                <SummaryCard label="MX-Server" value={gs.mx_count} />
                <SummaryCard label="IPs" value={gs.ip_count} />
                <SummaryCard label="ASNs" value={gs.asn_count} />
                <SummaryCard
                  label="DKIM"
                  value={gs.dkim_selectors_found > 0 ? `${gs.dkim_selectors_found} Sel.` : "—"}
                  sub={
                    gs.dkim_weak_keys > 0
                      ? `${gs.dkim_weak_keys} schwach`
                      : gs.dkim_missing_providers?.length > 0
                        ? `⚠ ${gs.dkim_missing_providers[0]}${gs.dkim_missing_providers.length > 1 ? " +mehr" : ""} fehlt`
                        : gs.dkim_selectors_found > 0 ? "OK" : "nicht gefunden"
                  }
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
                <SummaryCard
                  label="DNSSEC"
                  value={gs.dnssec_signed ? "✓" : "—"}
                  sub={gs.dnssec_signed ? "signiert" : "nicht signiert"}
                />
              </div>
            )}

            {/* Consistency checks */}
            {activeResult.status === "complete" && (
              <ConsistencyChecks findings={activeResult.findings} gs={gs} />
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
                    {gs?.rua_external_domains?.length > 0 && (
                      <div style={{
                        display: "flex", alignItems: "center", gap: 6, marginTop: 6,
                        padding: "5px 8px", borderRadius: 4,
                        background: alpha(T.text3, 8), border: `1px solid ${alpha(T.text3, 15)}`,
                      }}>
                        <span style={{ fontFamily: T.font, fontSize: 10, color: T.text3 }}>ⓘ</span>
                        <span style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text3 }}>
                          Aggregate-Reports an externe Domain(s):&nbsp;
                          <strong>{gs.rua_external_domains.join(", ")}</strong>
                        </span>
                      </div>
                    )}
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
                      {["Prio", "FQDN / IP", "Provider · ASN", "PTR", "SPF", "MTA-STS"].map(h => (
                        <th key={h} style={{ padding: "6px 12px", textAlign: "left", fontFamily: T.fontSans, fontSize: 10, color: T.text4, textTransform: "uppercase" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {activeResult.mx_records.map(mx => {
                      const allSpfOk = (mx.ips || []).every(ip => ip.spf_covered !== false);
                      const mtaOk = mx.mta_sts_covered;
                      const mtaConfigured = !!gs?.mta_sts_mode;
                      const ips = mx.ips || [];
                      return (
                        <tr key={mx.fqdn} style={{ borderBottom: `1px solid ${T.border}`, verticalAlign: "top" }}>
                          {/* Prio */}
                          <td style={{ padding: "10px 12px", fontFamily: T.font, fontSize: 11, color: T.text3, whiteSpace: "nowrap" }}>
                            {mx.priority}
                          </td>
                          {/* FQDN + IPs */}
                          <td style={{ padding: "10px 12px" }}>
                            <div style={{ fontFamily: T.font, fontSize: 11, color: T.text1, marginBottom: ips.length ? 4 : 0 }}>
                              {mx.fqdn}
                            </div>
                            {ips.map(ip => (
                              <div key={ip.address} style={{ display: "flex", alignItems: "center", gap: 4, marginTop: 2 }}>
                                <span style={{
                                  fontFamily: T.font, fontSize: 9, padding: "1px 4px",
                                  borderRadius: 3, border: `1px solid ${T.border}`,
                                  color: T.text4, background: T.bg3, flexShrink: 0,
                                }}>
                                  {ip.version === 6 ? "IPv6" : "IPv4"}
                                </span>
                                <span style={{ fontFamily: T.font, fontSize: 10, color: ip.spf_covered === false ? "var(--critical)" : T.text3 }}>
                                  {ip.spf_covered === false ? "✗ " : ""}{ip.address}
                                </span>
                              </div>
                            ))}
                          </td>
                          {/* Provider · ASN */}
                          <td style={{ padding: "10px 12px" }}>
                            {ips.map(ip => (
                              <div key={ip.address} style={{ marginTop: 2, lineHeight: 1.3 }}>
                                {ip.provider_name && ip.provider_name !== "Unknown" ? (
                                  <div style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text2 }}>
                                    {ip.provider_name}
                                  </div>
                                ) : null}
                                {ip.asn ? (
                                  <div style={{ fontFamily: T.font, fontSize: 9, color: T.text4 }}>
                                    AS{ip.asn.number}
                                    {ip.asn.name ? ` · ${ip.asn.name}` : ""}
                                    {ip.asn.country ? ` (${ip.asn.country})` : ""}
                                  </div>
                                ) : (
                                  <div style={{ fontFamily: T.font, fontSize: 9, color: T.text4 }}>—</div>
                                )}
                              </div>
                            ))}
                          </td>
                          {/* PTR */}
                          <td style={{ padding: "10px 12px" }}>
                            {ips.map(ip => (
                              <div key={ip.address} style={{ fontFamily: T.font, fontSize: 9, color: T.text4, marginTop: 2, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={ip.ptr || ""}>
                                {ip.ptr || <span style={{ color: T.text4, opacity: 0.5 }}>—</span>}
                              </div>
                            ))}
                          </td>
                          {/* SPF */}
                          <td style={{ padding: "10px 12px", fontFamily: T.font, fontSize: 12, fontWeight: 700, color: allSpfOk ? "#22c55e" : "var(--critical)", whiteSpace: "nowrap" }}>
                            {allSpfOk ? "✓" : "✗"}
                          </td>
                          {/* MTA-STS */}
                          <td style={{ padding: "10px 12px", fontFamily: T.font, fontSize: 12, fontWeight: 700, color: !mtaConfigured ? T.text4 : mtaOk ? "#22c55e" : "#f59e0b", whiteSpace: "nowrap" }}>
                            {!mtaConfigured ? "—" : mtaOk ? "✓" : "✗"}
                          </td>
                        </tr>
                      );
                    })}
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
