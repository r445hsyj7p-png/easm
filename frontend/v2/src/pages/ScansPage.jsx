import { useState, useEffect, useRef, useCallback } from "react";
import { RefreshCw, Play, CheckCircle, XCircle, Clock, Loader, X, AlertTriangle, ChevronRight } from "lucide-react";
import { toast } from "sonner";
import { T, alpha } from "../theme";
import { Card, CardHeader, TH, TD, EmptyState, PageLoading, Btn } from "../components/ui/index";
import { ScanModeToggle, ScanModeBadge, parseScanType } from "../components/ui/ScanModeToggle";
import { useApp } from "../context/AppContext";
import { apiFetch } from "../api/client";

const STATUS_ICON = {
  pending:   { Icon: Clock,       color: T.text3   },
  running:   { Icon: Loader,      color: T.medium, spin: true },
  completed: { Icon: CheckCircle, color: T.accent  },
  failed:    { Icon: XCircle,     color: T.critical },
  cancelled: { Icon: XCircle,     color: T.text3   },
};

function StatusCell({ status }) {
  const cfg = STATUS_ICON[status] || STATUS_ICON.pending;
  const { Icon, color, spin } = cfg;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <Icon size={13} color={color} style={spin ? { animation: "spin 1s linear infinite" } : {}} />
      <span style={{ fontFamily: T.font, fontSize: 10, fontWeight: 700, color }}>{(status || "—").toUpperCase()}</span>
    </div>
  );
}

function fmtDuration(secs) {
  if (secs == null || secs < 0) return "—";
  if (secs < 60) return `${secs}s`;
  return `${Math.floor(secs / 60)}m ${secs % 60}s`;
}

function fmtDatetime(started, finished) {
  if (!started) return "—";
  const end = finished ? new Date(finished) : new Date();
  const ms  = end - new Date(started);
  if (ms < 0) return "—";
  return fmtDuration(Math.floor(ms / 1000));
}

export default function ScansPage() {
  const { scans: initialScans, loading, triggerScan, tenantId } = useApp();
  const [scans,    setScans]    = useState(null);
  const [scanning, setScanning] = useState(false);
  const [detail,   setDetail]   = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [scanMode, setScanMode] = useState(
    () => localStorage.getItem("easm_scan_mode") || "active"
  );
  const intervalRef = useRef(null);
  const scansRef    = useRef(null);

  const handleModeChange = (m) => {
    setScanMode(m);
    localStorage.setItem("easm_scan_mode", m);
  };

  useEffect(() => { scansRef.current = scans; }, [scans]);
  useEffect(() => { if (initialScans) setScans(initialScans); }, [initialScans]);

  // Poll while running/pending jobs exist
  useEffect(() => {
    const poll = async () => {
      const hasRunning = (scansRef.current || []).some(
        s => s.status === "running" || s.status === "pending"
      );
      if (!hasRunning) { clearInterval(intervalRef.current); intervalRef.current = null; return; }
      try {
        const data = await apiFetch(`/tenants/${tenantId}/scans?limit=20`);
        setScans(data.scans ?? data);
        // Refresh detail if it's for a running scan
        if (detail && ["running", "pending"].includes(detail.status)) {
          const fresh = await apiFetch(`/tenants/${tenantId}/scans/${detail.id}`);
          setDetail(fresh);
        }
      } catch { /* ignore */ }
    };
    clearInterval(intervalRef.current);
    intervalRef.current = setInterval(poll, 5000);
    return () => { clearInterval(intervalRef.current); intervalRef.current = null; };
  }, [tenantId, detail]);

  const loadDetail = useCallback(async (scanId) => {
    setDetailLoading(true);
    try {
      const data = await apiFetch(`/tenants/${tenantId}/scans/${scanId}`);
      setDetail(data);
    } catch (e) {
      toast.error("Scan-Detail konnte nicht geladen werden", { description: e.message });
    } finally {
      setDetailLoading(false);
    }
  }, [tenantId]);

  if (loading && !scans) return <PageLoading />;

  const displayScans = scans || initialScans || [];

  const handleScan = async (type) => {
    // quick is always passive; full/other respect current scanMode toggle
    const mode = type === "quick" ? "passive" : scanMode;
    setScanning(true);
    try {
      const job = await triggerScan(type, mode);
      setScans(prev => [job, ...(prev || [])]);
      const modeLabel = mode === "passive" ? "Passiv" : "Aktiv";
      toast.success(`${type === "full" ? "Full Scan" : "Quick Scan"} (${modeLabel}) gestartet`, {
        description: `Job ID: ${job.id || job.scan_id}`,
      });
    } catch (e) {
      toast.error("Scan fehlgeschlagen", { description: e.message });
    } finally {
      setScanning(false);
    }
  };

  return (
    <div style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
      {/* Main content */}
      <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", gap: 20 }}>
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <div style={{ fontFamily: T.fontSans, fontSize: 18, fontWeight: 700, color: T.text0, marginBottom: 4 }}>
              Scan-Verlauf
            </div>
            <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>
              {displayScans.length} Scans · Zeile anklicken für Details
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <ScanModeToggle mode={scanMode} onChange={handleModeChange} size="sm" />
            <div style={{ width: 1, height: 24, background: T.border }} />
            <Btn onClick={() => handleScan("quick")} disabled={scanning}>
              <Play size={12} />Quick Scan
            </Btn>
            <Btn onClick={() => handleScan("full")} variant="primary" disabled={scanning}>
              <RefreshCw size={12} style={scanning ? { animation: "spin 1s linear infinite" } : {}} />
              {scanning ? "Läuft…" : "Full Scan"}
            </Btn>
          </div>
        </div>

        {/* Table */}
        <Card>
          <CardHeader title="Scan-Jobs" />
          {displayScans.length === 0 ? (
            <EmptyState icon={RefreshCw} title="Noch kein Scan" sub="Starte deinen ersten Scan mit dem Button oben." />
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    <TH>Scan-ID</TH>
                    <TH>Typ</TH>
                    <TH>Status</TH>
                    <TH>Gestartet</TH>
                    <TH>Dauer</TH>
                    <TH>Findings</TH>
                    <TH>Assets</TH>
                    <TH></TH>
                  </tr>
                </thead>
                <tbody>
                  {displayScans.map(scan => {
                    const isSelected = detail?.id === (scan.id || scan.scan_id);
                    const startedStr = scan.started_at || scan.created_at
                      ? new Date(scan.started_at || scan.created_at).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" })
                      : "—";
                    const stats    = scan.stats || scan.tool_stats || {};
                    const findings = scan.findings_count ?? Object.values(stats).reduce((s, v) => s + (v?.findings || 0), 0);
                    const assets   = scan.assets_count   ?? Object.values(stats).reduce((s, v) => s + (v?.assets   || 0), 0);
                    const { type: scanBaseType, mode: scanHistMode } =
                      parseScanType(scan.scan_type || scan.type || "full");

                    return (
                      <tr key={scan.id || scan.scan_id}
                        onClick={() => loadDetail(scan.id || scan.scan_id)}
                        style={{
                          cursor: "pointer",
                          background: isSelected ? T.bg3 : "transparent",
                          transition: "background 0.1s",
                        }}
                        onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = T.bg3; }}
                        onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = "transparent"; }}
                      >
                        <TD style={{ fontFamily: T.font, fontSize: 10, color: T.text3 }}>
                          {(scan.id || scan.scan_id || "—").toString().slice(0, 8)}…
                        </TD>
                        <TD>
                          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                            <span style={{
                              fontFamily: T.font, fontSize: 10, color: T.text2,
                              background: T.bg4, border: `1px solid ${T.border}`,
                              padding: "1px 7px", borderRadius: 3,
                            }}>{scanBaseType}</span>
                            <ScanModeBadge mode={scanHistMode} />
                          </div>
                        </TD>
                        <TD><StatusCell status={scan.status} /></TD>
                        <TD style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text2 }}>{startedStr}</TD>
                        <TD style={{ fontFamily: T.font, fontSize: 11, color: T.text3 }}>
                          {scan.duration_seconds != null
                            ? fmtDuration(scan.duration_seconds)
                            : fmtDatetime(scan.started_at || scan.created_at, scan.finished_at || scan.completed_at)}
                        </TD>
                        <TD style={{ fontFamily: T.font, fontSize: 12, fontWeight: 700, color: findings > 0 ? T.medium : T.text3 }}>
                          {findings || 0}
                        </TD>
                        <TD style={{ fontFamily: T.font, fontSize: 12, fontWeight: 700, color: assets > 0 ? T.accent : T.text3 }}>
                          {assets || 0}
                        </TD>
                        <TD>
                          <ChevronRight size={13} color={isSelected ? T.accent : T.text4} />
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

      {/* Detail drawer */}
      {(detail || detailLoading) && (
        <div style={{
          width: 380, flexShrink: 0, background: T.bg2,
          border: `1px solid ${T.border}`, borderRadius: 8, overflow: "hidden",
          position: "sticky", top: 0, animation: "slideIn 0.15s ease",
        }}>
          {/* Header */}
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "14px 16px", borderBottom: `1px solid ${T.border}`, background: T.bg3,
          }}>
            <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 700, color: T.text0 }}>
              Scan-Detail
            </div>
            <button onClick={() => setDetail(null)} style={{
              background: "none", border: "none", color: T.text3, cursor: "pointer",
            }}><X size={16} /></button>
          </div>

          {detailLoading ? (
            <div style={{ padding: 24, fontFamily: T.font, fontSize: 11, color: T.text3 }}>Lädt…</div>
          ) : detail && (
            <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: 16, maxHeight: "calc(100vh - 180px)", overflowY: "auto" }}>
              {/* Status + type */}
              <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <StatusCell status={detail.status} />
                <span style={{
                  fontFamily: T.font, fontSize: 10, color: T.text2,
                  background: T.bg4, border: `1px solid ${T.border}`,
                  padding: "1px 7px", borderRadius: 3,
                }}>{detail.scan_type || "full"}</span>
                <span style={{ fontFamily: T.font, fontSize: 10, color: T.text3, marginLeft: "auto" }}>
                  {detail.id?.slice(0, 8)}…
                </span>
              </div>

              {/* Progress bar (running scans) */}
              {["running", "pending"].includes(detail.status) && (
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text2 }}>
                      {detail.current_phase || "Vorbereitung…"}
                    </span>
                    <span style={{ fontFamily: T.font, fontSize: 11, color: T.accent }}>
                      {detail.progress_pct ?? 0}%
                    </span>
                  </div>
                  <div style={{ height: 4, background: T.bg4, borderRadius: 2, overflow: "hidden" }}>
                    <div style={{
                      width: `${detail.progress_pct ?? 0}%`, height: "100%",
                      background: T.accent, borderRadius: 2, transition: "width 0.5s ease",
                    }} />
                  </div>
                </div>
              )}

              {/* Error */}
              {detail.error_message && (
                <div style={{
                  display: "flex", gap: 8, alignItems: "flex-start",
                  background: T.criticalBg, border: `1px solid ${T.criticalBorder}`,
                  borderRadius: 6, padding: "10px 12px",
                }}>
                  <AlertTriangle size={13} color={T.critical} style={{ flexShrink: 0, marginTop: 1 }} />
                  <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.critical, lineHeight: 1.5 }}>
                    {detail.error_message}
                  </span>
                </div>
              )}

              {/* Stats grid */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                {[
                  { label: "Findings",  value: detail.findings_count ?? "—", color: detail.findings_count > 0 ? T.medium : T.text3 },
                  { label: "Risk Score",value: detail.risk_score     != null ? detail.risk_score.toFixed(1) : "—", color: T.accent },
                  { label: "Dauer",     value: fmtDuration(detail.duration_seconds), color: T.text1 },
                  { label: "Phase",     value: detail.current_phase || "—", color: T.text2 },
                ].map(({ label, value, color }) => (
                  <div key={label} style={{
                    background: T.bg3, border: `1px solid ${T.border}`,
                    borderRadius: 6, padding: "10px 12px",
                  }}>
                    <div style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text3, marginBottom: 4 }}>{label}</div>
                    <div style={{ fontFamily: T.font, fontSize: 16, fontWeight: 700, color }}>{value}</div>
                  </div>
                ))}
              </div>

              {/* Timestamps */}
              <div>
                <DRow label="Gestartet"   value={detail.started_at  ? new Date(detail.started_at).toLocaleString("de-DE")  : "—"} />
                <DRow label="Beendet"     value={detail.finished_at ? new Date(detail.finished_at).toLocaleString("de-DE") : "—"} />
              </div>

              {/* Scan log */}
              {detail.scan_log?.length > 0 && (
                <div>
                  <div style={{ fontFamily: T.font, fontSize: 9, color: T.text4, letterSpacing: "0.08em", marginBottom: 8 }}>
                    SCAN-LOG ({detail.scan_log.length} Einträge)
                  </div>
                  <div style={{
                    background: T.bg3, border: `1px solid ${T.border}`,
                    borderRadius: 6, maxHeight: 200, overflowY: "auto", padding: "8px 0",
                  }}>
                    {detail.scan_log.map((entry, i) => {
                      const msg = typeof entry === "string" ? entry : (entry.message || entry.msg || JSON.stringify(entry));
                      const ts  = typeof entry === "object" && entry.timestamp
                        ? new Date(entry.timestamp).toLocaleTimeString("de-DE")
                        : null;
                      return (
                        <div key={i} style={{
                          display: "flex", gap: 8, padding: "3px 12px",
                          borderBottom: i < detail.scan_log.length - 1 ? `1px solid ${T.border}` : "none",
                        }}>
                          {ts && <span style={{ fontFamily: T.font, fontSize: 9, color: T.text4, flexShrink: 0 }}>{ts}</span>}
                          <span style={{ fontFamily: T.font, fontSize: 10, color: T.text2, wordBreak: "break-all", lineHeight: 1.4 }}>
                            {msg}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function DRow({ label, value }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: `1px solid ${T.border}` }}>
      <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3 }}>{label}</span>
      <span style={{ fontFamily: T.font, fontSize: 11, color: T.text1 }}>{value}</span>
    </div>
  );
}
