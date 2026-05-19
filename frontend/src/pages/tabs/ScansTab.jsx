import { useState, useRef, useEffect, useCallback } from "react";
import { toast } from "sonner";
import { Play, Loader2, CheckCircle, XCircle, Circle, AlertTriangle } from "lucide-react";
import { T, TOOL_COLOR } from "../../theme";
import { useApp } from "../../context/AppContext";
import { apiFetch } from "../../api/client";

const ScanTimeline = ({ scans }) => (
  <div style={{ display:"flex", flexDirection:"column", gap:0 }}>
    {scans.map((s,i) => (
      <div key={s.id || i} style={{ display:"flex", gap:10, position:"relative" }}>
        <div style={{ display:"flex", flexDirection:"column", alignItems:"center", width:16 }}>
          {s.status==="completed" ? <CheckCircle size={12} color={T.accent}    style={{ flexShrink:0, marginTop:2 }} /> :
           s.status==="running"   ? <Loader2    size={12} color={T.accent}    style={{ flexShrink:0, marginTop:2, animation:"spin 1s linear infinite" }} /> :
           s.status==="error"     ? <XCircle    size={12} color={T.critical}  style={{ flexShrink:0, marginTop:2 }} /> :
                                    <Circle     size={12} color={T.text3}     style={{ flexShrink:0, marginTop:2 }} />}
          {i < scans.length-1 && <div style={{ width:1, flex:1, background:T.border, marginTop:2 }}/>}
        </div>
        <div style={{ flex:1, paddingBottom:14 }}>
          <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:4 }}>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:T.text0, fontWeight:600 }}>{s.label}</span>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9,
              color: s.status==="completed" ? T.accent : s.status==="error" ? T.critical : T.text3 }}>
              {s.status}
            </span>
            <span style={{ marginLeft:"auto", fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3 }}>{s.time}</span>
          </div>
          <div style={{ display:"flex", gap:5, flexWrap:"wrap" }}>
            {(s.tags||[]).map(tag => (
              <span key={tag} style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9,
                color:T.text2, background:T.bg3, border:`1px solid ${T.border}`,
                padding:"1px 6px", borderRadius:3 }}>{tag}</span>
            ))}
          </div>
        </div>
      </div>
    ))}
  </div>
);

const ALL_PHASES = [
  { key:"discovery", label:"Discovery",    tool:"subfinder + theHarvester", color:T.accent,     pct:[0,20]  },
  { key:"portscan",  label:"Port Scan",    tool:"naabu SYN-Scan + UDP",     color:T.medium,     pct:[20,35] },
  { key:"tls",       label:"TLS Scan",     tool:"sslyze — cipher + cert",   color:T.toolSslyze, pct:[35,50] },
  { key:"http",      label:"HTTP Probing", tool:"httpx + screenshots",      color:T.toolHttpx,  pct:[50,70] },
  { key:"vuln",      label:"Vuln Scan",    tool:"nuclei 7000+ templates",   color:T.critical,   pct:[70,88] },
  { key:"mcp",       label:"MCP Analysis", tool:"ramparts + handshake",     color:T.high,       pct:[88,99] },
];

const LOG_COLORS = { info: T.text2, warn: T.medium, error: T.critical };
const DEFAULT_SELECTED = { discovery:true, portscan:true, tls:true, http:true, vuln:true, mcp:true };

function useElapsed(startedAt) {
  const [secs, setSecs] = useState(0);
  useEffect(() => {
    if (!startedAt) { setSecs(0); return; }
    const base = new Date(startedAt).getTime();
    const tick = () => setSecs(Math.floor((Date.now() - base) / 1000));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startedAt]);
  return secs;
}

const ScansTab = () => {
  const { tenant, triggerScan, scans, tenantId, refresh } = useApp();

  const mappedScans = (Array.isArray(scans) ? scans : []).slice(0, 10).map(s => ({
    id: s.id,
    label: `${s.started_at ? s.started_at.slice(0, 16).replace("T", " ") : "—"} — ${(s.scan_type || "full").replace(/_/g, " ")} Scan`,
    status: s.status || "pending",
    time: s.duration_seconds ? `${s.duration_seconds}s` : "—",
    tags: [
      s.findings_count != null ? `${s.findings_count} findings` : null,
      s.risk_score     != null ? `score: ${s.risk_score}`       : null,
    ].filter(Boolean),
  }));

  const [selected,      setSelected]      = useState(DEFAULT_SELECTED);

  const [scanId,        setScanId]        = useState(null);
  const [scanStatus,    setScanStatus]    = useState(null);
  const [scanStartedAt, setScanStartedAt] = useState(null);

  const pollRef = useRef(null);
  const logRef  = useRef(null);

  const elapsed = useElapsed(scanStartedAt);

  const realPct = scanStatus?.progress_pct ?? 0;
  const displayPct = realPct;

  const activePhaseKeys = ALL_PHASES.filter(ph => selected[ph.key]).map(ph => ph.key);
  const realPhaseLocalIdx = activePhaseKeys.indexOf(scanStatus?.current_phase ?? "");

  const isActive = scanStatus?.status === "running" || scanStatus?.status === "pending";
  const isDone   = scanStatus?.status === "completed";
  const isError  = scanStatus?.status === "error";

  // -1 when idle so no phase block is highlighted before a scan starts
  const displayPhaseIdx = realPhaseLocalIdx >= 0 ? realPhaseLocalIdx : (isActive ? 0 : -1);

  const activePhases = ALL_PHASES.filter(ph => selected[ph.key]);

  const togglePhase = (key) => {
    if (isActive) return;
    setSelected(prev => {
      const next = { ...prev, [key]: !prev[key] };
      if (Object.values(next).every(v => !v)) return prev;
      return next;
    });
  };

  const startPolling = useCallback((id) => {
    if (pollRef.current) clearInterval(pollRef.current);

    const poll = async () => {
      try {
        const data = await apiFetch(`/tenants/${tenantId}/scans/${id}`);
        setScanStatus(data);
        if (data.started_at) setScanStartedAt(data.started_at);

        if (data.status === "completed") {
          clearInterval(pollRef.current); pollRef.current = null;
          const cnt   = data.findings_count ?? "—";
          const score = data.risk_score     ?? "—";
          const dur   = data.duration_seconds ? `${data.duration_seconds}s` : "";
          toast.success(`Scan abgeschlossen ${dur ? `(${dur})` : ""}`, {
            description: `${cnt} Findings · Risk Score: ${score}`,
            duration: 10000,
          });
          refresh();
        } else if (data.status === "error") {
          clearInterval(pollRef.current); pollRef.current = null;
          toast.error("Scan fehlgeschlagen", { description: data.error_message || "Unbekannter Fehler" });
        }
      } catch {
        // ignore transient poll errors
      }
    };

    poll();
    pollRef.current = setInterval(poll, 5000);
  }, [tenantId, refresh]);

  const startScan = async () => {
    if (isActive || activePhases.length === 0) return;

    const scanType = activePhases.length === ALL_PHASES.length
      ? "full"
      : activePhases.map(p => p.key).join(",");

    setScanStatus({ status: "pending", progress_pct: 0, current_phase: "starting", scan_log: [] });
    setScanStartedAt(new Date().toISOString());
    setScanId(null);

    try {
      const job = await triggerScan(scanType);
      setScanId(job.id);
      toast.info("Scan gestartet", { description: "Status wird alle 5s aktualisiert." });
      startPolling(job.id);
    } catch (e) {
      toast.error("Scan-Dispatch fehlgeschlagen", { description: e.message });
      setScanStatus(null);
      setScanStartedAt(null);
    }
  };

  useEffect(() => () => { clearInterval(pollRef.current); }, []);

  // Auto-scroll log panel
  const scanLog = Array.isArray(scanStatus?.scan_log) ? scanStatus.scan_log : [];
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [scanLog.length]);

  const findingsCount = (() => {
    const fc = scanStatus?.findings_count;
    if (fc == null) return "—";
    if (typeof fc === "object") return Object.values(fc).reduce((a, b) => a + (Number(b) || 0), 0);
    return fc;
  })();

  const statusText = () => {
    if (isDone)  return `✓ Abgeschlossen · ${findingsCount} Findings · Score: ${scanStatus?.risk_score ?? "—"}`;
    if (isError) return `✗ Fehler: ${scanStatus?.error_message || "Unbekannt"}`;
    if (isActive) {
      const phaseName = scanStatus?.current_phase || "";
      const ph = activePhases[displayPhaseIdx];
      return phaseName ? `[${phaseName}] ${ph?.tool ?? ""}` : (ph?.tool ?? "");
    }
    return `${activePhases.length} von ${ALL_PHASES.length} Modulen ausgewählt`;
  };

  const barColor = isError ? T.critical : T.accent;

  return (
    <div style={{ display:"grid", gridTemplateColumns:"1fr 360px", gap:16, alignItems:"flex-start" }}>
      <div style={{ display:"flex", flexDirection:"column", gap:14 }}>

        <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:16 }}>
          <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3,
            letterSpacing:"0.08em", marginBottom:12 }}>SCAN MODULES — AUSWAHL</div>
          <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
            {ALL_PHASES.map(ph => {
              const on = selected[ph.key];
              return (
                <button key={ph.key} onClick={() => togglePhase(ph.key)} disabled={isActive} style={{
                  display:"flex", alignItems:"center", gap:6,
                  background: on ? `${ph.color}15` : T.bg3,
                  border:`1px solid ${on ? ph.color : T.border}`,
                  borderRadius:4, padding:"6px 12px",
                  cursor: isActive ? "not-allowed" : "pointer",
                  opacity: isActive ? 0.7 : 1,
                  transition:"all 0.15s",
                }}>
                  <div style={{ width:6, height:6, borderRadius:"50%", background: on ? ph.color : T.text3, flexShrink:0 }}/>
                  <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9,
                    color: on ? ph.color : T.text3, fontWeight: on ? 700 : 400 }}>{ph.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:20 }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 }}>
            <div>
              <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:14, fontWeight:600, color:T.text0 }}>Scan Pipeline</div>
              <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3, marginTop:3 }}>
                {tenant?.domain || tenant?.name || "—"} · {activePhases.map(p => p.label).join(" · ")}
              </div>
            </div>
            <div style={{ display:"flex", alignItems:"center", gap:10 }}>
              {isActive && (
                <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:10, color:T.text2 }}>
                  {Math.floor(elapsed / 60)}:{String(elapsed % 60).padStart(2,"0")} elapsed
                </span>
              )}
              <button onClick={startScan} disabled={isActive || activePhases.length === 0} style={{
                background: isActive ? T.bg3 : T.accent,
                border:"none", borderRadius:4, padding:"9px 24px",
                fontFamily:"'JetBrains Mono',monospace", fontSize:11, fontWeight:700,
                color: isActive ? T.text2 : T.bg0,
                cursor: (isActive || activePhases.length === 0) ? "not-allowed" : "pointer",
                letterSpacing:"0.06em",
                display:"flex", alignItems:"center", gap:7,
              }}>
                {isActive
                  ? <><Loader2 size={13} style={{ animation:"spin 1s linear infinite" }} />SCANNING… {displayPct}%</>
                  : <><Play size={13} />START SCAN</>}
              </button>
            </div>
          </div>

          <div style={{ height:3, background:T.bg4, borderRadius:2, overflow:"hidden", marginBottom:8 }}>
            <div style={{ height:"100%", background: barColor, borderRadius:2,
              width:`${isDone ? 100 : displayPct}%`, transition:"width 0.6s ease" }}/>
          </div>
          <div style={{ display:"flex", justifyContent:"space-between", marginBottom:16 }}>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9,
              color: isError ? T.critical : T.text3, maxWidth:"80%" }}>
              {statusText()}
            </span>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.accent }}>
              {isDone ? "100%" : `${displayPct}%`}
            </span>
          </div>

          <div style={{ display:"flex", gap:6 }}>
            {activePhases.map((ph, i) => {
              const done   = isDone || (displayPct >= ph.pct[1]);
              const active = isActive && displayPhaseIdx === i;
              return (
                <div key={ph.key} style={{
                  flex:1, padding:"10px 10px 9px",
                  background: done ? `${ph.color}10` : T.bg3,
                  border:`1px solid ${active ? ph.color : done ? `${ph.color}35` : T.border}`,
                  borderTop:`2px solid ${active || done ? ph.color : T.border}`,
                  borderRadius:4, transition:"all 0.4s",
                }}>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:7,
                    color:ph.color, letterSpacing:"0.08em", marginBottom:4 }}>P{i+1}</div>
                  <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:10, fontWeight:600,
                    color: active || done ? T.text0 : T.text3, marginBottom:2 }}>{ph.label}</div>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, color:T.text3 }}>{ph.tool}</div>
                  <div style={{ marginTop:5, display:"flex", alignItems:"center", gap:4,
                    fontFamily:"'JetBrains Mono',monospace", fontSize:9,
                    color: done ? T.accent : active ? T.accent : T.text3 }}>
                    {done   ? <><CheckCircle size={9} />done</> :
                     active ? <><Loader2 size={9} style={{ animation:"spin 1s linear infinite" }} />running…</> :
                     "pending"}
                  </div>
                </div>
              );
            })}
          </div>

          {isDone && scanStatus && (
            <div style={{ marginTop:12, display:"flex", gap:16, padding:"10px 14px",
              background:T.bg3, border:`1px solid ${T.accent}22`, borderRadius:4 }}>
              {[
                ["findings",      findingsCount],
                ["risk score",    scanStatus.risk_score ?? "—"],
                ["duration",      scanStatus.duration_seconds ? `${scanStatus.duration_seconds}s` : "—"],
              ].map(([label, val]) => (
                <div key={label}>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:8, color:T.text3, marginBottom:2 }}>{label.toUpperCase()}</div>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:13, fontWeight:700, color:T.accent }}>{val}</div>
                </div>
              ))}
            </div>
          )}

          {isError && (
            <div style={{ marginTop:12, display:"flex", alignItems:"center", gap:8, padding:"10px 14px",
              background:`${T.critical}10`, border:`1px solid ${T.critical}30`, borderRadius:4 }}>
              <AlertTriangle size={14} color={T.critical} />
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:10, color:T.critical }}>
                {scanStatus?.error_message || "Scan fehlgeschlagen"}
              </span>
            </div>
          )}
        </div>

        {/* Live scan log — real data from backend */}
        <div style={{ background:T.bg0, border:`1px solid ${T.border}`, borderRadius:6, overflow:"hidden" }}>
          <div style={{ padding:"8px 16px", borderBottom:`1px solid ${T.border}`, background:T.bg2,
            display:"flex", justifyContent:"space-between", alignItems:"center" }}>
            <div style={{ display:"flex", gap:6, alignItems:"center" }}>
              {["#ff5f56","#ffbd2e","#27c93f"].map((c,i) => (
                <div key={i} style={{ width:10, height:10, borderRadius:"50%", background:c, opacity:0.8 }}/>
              ))}
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3, marginLeft:6, letterSpacing:"0.08em" }}>
                SCAN LOG — LIVE
              </span>
            </div>
            <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3 }}>{scanLog.length} lines</span>
          </div>
          <div ref={logRef} style={{ padding:"14px 18px", fontFamily:"'JetBrains Mono',monospace",
            fontSize:11, lineHeight:1.9, minHeight:240, maxHeight:340, overflowY:"auto" }}>
            {scanLog.length === 0 ? (
              <span style={{ color:T.text3 }}>$ ./easm-pipeline run --domain {tenant?.domain || "—"} --modules {activePhases.map(p => p.key).join(",")}</span>
            ) : scanLog.map((line, i) => (
              <div key={i} style={{ color: LOG_COLORS[line.level] || T.text2 }}>
                <span style={{ color:T.text3, userSelect:"none" }}>[{line.ts || String(i+1).padStart(2,"0")}] </span>
                <span style={{ color:T.border2 }}>[{line.t}]</span>
                {"          ".slice(0, Math.max(2, 14 - (line.t||"").length))}
                <span>{line.msg}</span>
                {i === scanLog.length-1 && isActive && <span style={{ animation:"pulse 0.7s infinite" }}> ▮</span>}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
        <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:20 }}>
          <div style={{ fontFamily:"'IBM Plex Sans',sans-serif", fontSize:13, fontWeight:600, color:T.text0, marginBottom:14 }}>Scan History</div>
          <ScanTimeline scans={mappedScans} />
        </div>
        <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:6, padding:16 }}>
          <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3, letterSpacing:"0.08em", marginBottom:12 }}>TOOL BREAKDOWN — LAST SCAN</div>
          {Object.entries(tenant?.tool_stats || {}).map(([tool, stats]) => (
            <div key={tool} style={{ display:"flex", alignItems:"center", gap:10, marginBottom:10, paddingBottom:10, borderBottom:`1px solid ${T.border}` }}>
              <div style={{ width:5, height:5, borderRadius:"50%", background:TOOL_COLOR[tool], flexShrink:0 }}/>
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:TOOL_COLOR[tool], fontWeight:700, width:92 }}>{tool}</span>
              <div style={{ flex:1, height:2, background:T.bg4, borderRadius:2 }}>
                <div style={{ width:`${(stats.findings / 12) * 100}%`, height:"100%", background:TOOL_COLOR[tool], borderRadius:2 }}/>
              </div>
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color: stats.findings > 5 ? T.high : T.text2, fontWeight:700, minWidth:18 }}>{stats.findings}F</span>
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:T.text3 }}>{stats.duration}s</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ScansTab;
