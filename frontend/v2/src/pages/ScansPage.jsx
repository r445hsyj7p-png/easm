import { useState, useEffect, useRef } from "react";
import { RefreshCw, Play, CheckCircle, XCircle, Clock, Loader } from "lucide-react";
import { toast } from "sonner";
import { T } from "../theme";
import { Card, CardHeader, TH, TD, EmptyState, PageLoading, Btn } from "../components/ui/index";
import { useApp } from "../context/AppContext";
import { apiFetch } from "../api/client";

const STATUS_ICON = {
  pending:    { Icon: Clock,       color: T.text3  },
  running:    { Icon: Loader,      color: T.medium, spin: true },
  completed:  { Icon: CheckCircle, color: T.accent },
  failed:     { Icon: XCircle,     color: T.critical },
  cancelled:  { Icon: XCircle,     color: T.text3  },
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

function formatDuration(startedAt, finishedAt) {
  if (!startedAt) return "—";
  const end = finishedAt ? new Date(finishedAt) : new Date();
  const ms  = end - new Date(startedAt);
  if (ms < 0) return "—";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${s % 60}s`;
}

export default function ScansPage() {
  const { scans: initialScans, loading, triggerScan, tenantId } = useApp();
  const [scans, setScans]       = useState(null);
  const [scanning, setScanning] = useState(false);
  const intervalRef             = useRef(null);
  const scansRef                = useRef(null);

  // Keep ref in sync so the poll callback always sees latest scans without being a dep
  useEffect(() => { scansRef.current = scans; }, [scans]);

  // Merge in live data once loaded
  useEffect(() => {
    if (initialScans) setScans(initialScans);
  }, [initialScans]);

  // Poll only while running/pending jobs exist — no scans in deps to avoid interval churn
  useEffect(() => {
    const poll = async () => {
      const hasRunning = (scansRef.current || []).some(
        s => s.status === "running" || s.status === "pending"
      );
      if (!hasRunning) { clearInterval(intervalRef.current); intervalRef.current = null; return; }
      try {
        const data = await apiFetch(`/tenants/${tenantId}/scans?limit=20`);
        setScans(data.scans ?? data);
      } catch { /* ignore polling errors */ }
    };

    clearInterval(intervalRef.current);
    intervalRef.current = setInterval(poll, 5000);
    return () => { clearInterval(intervalRef.current); intervalRef.current = null; };
  }, [tenantId]);

  if (loading && !scans) return <PageLoading />;

  const displayScans = scans || initialScans || [];

  const handleScan = async (type) => {
    setScanning(true);
    try {
      const job = await triggerScan(type);
      setScans(prev => [job, ...(prev || [])]);
      toast.success(`${type === "full" ? "Full Scan" : "Quick Scan"} gestartet`, {
        description: `Job ID: ${job.id || job.scan_id}`,
      });
    } catch (e) {
      toast.error("Scan fehlgeschlagen", { description: e.message });
    } finally {
      setScanning(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Header row with scan buttons */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <div style={{ fontFamily: T.fontSans, fontSize: 18, fontWeight: 700, color: T.text0, marginBottom: 4 }}>
            Scan-Verlauf
          </div>
          <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>
            {displayScans.length} Scans gespeichert · Letzte 20 werden angezeigt
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Btn onClick={() => handleScan("quick")} disabled={scanning}>
            <Play size={12} />Quick Scan
          </Btn>
          <Btn onClick={() => handleScan("full")} variant="primary" disabled={scanning}>
            <RefreshCw size={12} style={scanning ? { animation: "spin 1s linear infinite" } : {}} />
            {scanning ? "Läuft…" : "Full Scan"}
          </Btn>
        </div>
      </div>

      {/* Scan table */}
      <Card>
        <CardHeader title="Scan-Jobs" sub="Klicken für Details" />
        {displayScans.length === 0 ? (
          <EmptyState
            icon={RefreshCw}
            title="Noch kein Scan"
            sub="Starte deinen ersten Scan mit dem Button oben."
          />
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
                  <TH>Tools</TH>
                </tr>
              </thead>
              <tbody>
                {displayScans.map(scan => {
                  const startedStr = scan.started_at || scan.created_at
                    ? new Date(scan.started_at || scan.created_at).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" })
                    : "—";
                  const stats   = scan.stats || scan.tool_stats || {};
                  const findings = scan.findings_count ?? Object.values(stats).reduce((s, v) => s + (v?.findings || 0), 0);
                  const assets   = scan.assets_count   ?? Object.values(stats).reduce((s, v) => s + (v?.assets   || 0), 0);
                  const toolList = Object.keys(stats);
                  return (
                    <tr key={scan.id || scan.scan_id}
                      style={{ transition: "background 0.1s" }}
                      onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      <TD style={{ fontFamily: T.font, fontSize: 10, color: T.text3 }}>
                        {(scan.id || scan.scan_id || "—").toString().slice(0, 8)}…
                      </TD>
                      <TD>
                        <span style={{
                          fontFamily: T.font, fontSize: 10, color: T.text2,
                          background: T.bg4, border: `1px solid ${T.border}`,
                          padding: "1px 7px", borderRadius: 3,
                        }}>{scan.scan_type || scan.type || "full"}</span>
                      </TD>
                      <TD><StatusCell status={scan.status} /></TD>
                      <TD style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text2 }}>{startedStr}</TD>
                      <TD style={{ fontFamily: T.font, fontSize: 11, color: T.text3 }}>
                        {formatDuration(scan.started_at || scan.created_at, scan.finished_at || scan.completed_at)}
                      </TD>
                      <TD style={{ fontFamily: T.font, fontSize: 12, fontWeight: 700, color: findings > 0 ? T.medium : T.text3 }}>
                        {findings || 0}
                      </TD>
                      <TD style={{ fontFamily: T.font, fontSize: 12, fontWeight: 700, color: assets > 0 ? T.accent : T.text3 }}>
                        {assets || 0}
                      </TD>
                      <TD>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                          {toolList.slice(0, 4).map(tool => (
                            <span key={tool} style={{
                              fontFamily: T.font, fontSize: 9, color: T.text2,
                              background: T.bg4, border: `1px solid ${T.border}`,
                              padding: "0 5px", borderRadius: 3,
                            }}>{tool}</span>
                          ))}
                          {toolList.length > 4 && (
                            <span style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>+{toolList.length - 4}</span>
                          )}
                          {toolList.length === 0 && (
                            <span style={{ fontFamily: T.font, fontSize: 9, color: T.text4 }}>—</span>
                          )}
                        </div>
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
