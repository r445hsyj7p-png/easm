import { useNavigate } from "react-router-dom";
import { AlertTriangle, Globe, Cpu, RefreshCw, TrendingUp, Clock } from "lucide-react";
import { T, SEV, SEV_ORDER } from "../theme";
import { KpiCard, Card, CardHeader, SevBadge, EmptyState, PageLoading } from "../components/ui/index";
import { useApp } from "../context/AppContext";

export default function DashboardPage() {
  const navigate = useNavigate();
  const { tenant, findings, assets, mcp, scans, loading } = useApp();

  if (loading) return <PageLoading />;

  const openFindings   = (findings || []).filter(f => f.status === "open");
  const criticalCount  = openFindings.filter(f => f.sev === "CRITICAL").length;
  const kevCount       = openFindings.filter(f => f.kev).length;
  const scoreColor     = (tenant.score || 0) >= 70 ? T.accent : (tenant.score || 0) >= 40 ? T.medium : T.critical;

  const lastScan = scans?.[0];
  const lastScanStr = tenant.last_scan
    ? new Date(tenant.last_scan).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" })
    : "—";
  const nextScanStr = tenant.next_scan
    ? new Date(tenant.next_scan).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" })
    : "—";

  const recentCritical = openFindings
    .filter(f => f.sev === "CRITICAL" || f.sev === "HIGH")
    .sort((a, b) => (SEV_ORDER[a.sev] ?? 9) - (SEV_ORDER[b.sev] ?? 9))
    .slice(0, 6);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* KPI row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
        <KpiCard
          label="Risk Score" value={tenant.score ?? "—"}
          sub={`Grade ${tenant.grade || "?"}`} color={scoreColor}
          icon={TrendingUp}
        />
        <KpiCard
          label="Open Findings" value={openFindings.length}
          sub={`${Object.values(tenant.findings_summary || {}).reduce((a, b) => a + b, 0)} gesamt`}
          onClick={() => navigate("/findings")} icon={AlertTriangle}
        />
        <KpiCard
          label="Critical" value={criticalCount}
          color={criticalCount > 0 ? T.critical : T.text2}
          sub="Offene Kritisch-Findings" onClick={() => navigate("/findings")}
        />
        <KpiCard
          label="KEV Findings" value={kevCount}
          color={kevCount > 0 ? T.red : T.text2}
          sub="CISA Known Exploited" onClick={() => navigate("/findings")}
        />
        <KpiCard
          label="Assets" value={tenant.assets?.subdomains ?? (assets || []).length}
          sub={`${tenant.assets?.ips || 0} IPs · ${tenant.assets?.ports || 0} Ports`}
          color={T.accent} onClick={() => navigate("/assets")} icon={Globe}
        />
      </div>

      {/* Second row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* Severity breakdown */}
        <Card>
          <CardHeader title="Findings nach Schweregrad" sub="Nur offene Findings" />
          <div style={{ padding: "16px 20px" }}>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map(sev => {
              const count = openFindings.filter(f => f.sev === sev).length;
              const maxVal = Math.max(...["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(
                s => openFindings.filter(f => f.sev === s).length
              ), 1);
              const s = SEV[sev];
              return (
                <div key={sev} onClick={() => navigate("/findings")}
                  style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12, cursor: "pointer" }}>
                  <div style={{ width: 72, flexShrink: 0 }}>
                    <SevBadge sev={sev} small />
                  </div>
                  <div style={{ flex: 1, height: 5, background: T.bg4, borderRadius: 3, overflow: "hidden" }}>
                    <div style={{
                      width: `${(count / maxVal) * 100}%`, height: "100%",
                      background: s.color, borderRadius: 3,
                      transition: "width 0.4s ease",
                    }} />
                  </div>
                  <span style={{ fontFamily: T.font, fontSize: 12, fontWeight: 700, color: s.color, minWidth: 24, textAlign: "right" }}>
                    {count}
                  </span>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Recent critical/high findings */}
        <Card>
          <CardHeader
            title="Kritische & Hohe Findings"
            sub="Offene Findings nach Priorität"
            actions={
              <button onClick={() => navigate("/findings")} style={{
                background: "transparent", border: `1px solid ${T.border}`,
                borderRadius: 4, padding: "4px 10px", fontFamily: T.font,
                fontSize: 10, color: T.text3, cursor: "pointer",
              }}>Alle →</button>
            }
          />
          <div style={{ padding: "8px 0" }}>
            {recentCritical.length === 0 ? (
              <EmptyState title="Keine kritischen Findings" sub="Keine offenen CRITICAL/HIGH Findings vorhanden." />
            ) : recentCritical.map(f => (
              <div key={f.id} onClick={() => navigate("/findings")}
                style={{
                  display: "flex", alignItems: "center", gap: 10,
                  padding: "9px 18px", cursor: "pointer",
                  borderBottom: `1px solid ${T.border}`,
                  transition: "background 0.1s",
                }}
                onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                <SevBadge sev={f.sev} small />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontFamily: T.fontSans, fontSize: 12, color: T.text0,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  }}>{f.title}</div>
                  <div style={{ fontFamily: T.font, fontSize: 10, color: T.text3, marginTop: 2 }}>
                    {f.asset || "—"}
                  </div>
                </div>
                {f.kev && (
                  <span style={{
                    fontFamily: T.font, fontSize: 9, fontWeight: 700,
                    color: T.critical, background: T.criticalBg,
                    border: `1px solid ${T.criticalBorder}`,
                    padding: "0 5px", borderRadius: 2, flexShrink: 0,
                  }}>KEV</span>
                )}
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Third row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16 }}>
        {/* Scan status */}
        <Card>
          <CardHeader title="Scan-Status" />
          <div style={{ padding: "16px 20px", display: "flex", flexDirection: "column", gap: 12 }}>
            <Row label="Letzter Scan" value={lastScanStr} icon={<Clock size={12} color={T.text3} />} />
            <Row label="Nächster Scan" value={nextScanStr} icon={<RefreshCw size={12} color={T.accent} />} valueColor={T.accent} />
            <Row label="Subdomains" value={tenant.assets?.subdomains ?? "—"} />
            <Row label="Unique IPs" value={tenant.assets?.ips ?? "—"} />
            <Row label="Offene Ports" value={tenant.assets?.ports ?? "—"} />
          </div>
        </Card>

        {/* Tool stats */}
        <Card>
          <CardHeader title="Tool-Statistiken" />
          <div style={{ padding: "8px 0" }}>
            {Object.keys(tenant.tool_stats || {}).length === 0 ? (
              <div style={{ padding: "24px 20px", fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>
                Noch kein Scan durchgeführt.
              </div>
            ) : Object.entries(tenant.tool_stats).map(([tool, stats]) => (
              <div key={tool} style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "8px 18px", borderBottom: `1px solid ${T.border}`,
              }}>
                <span style={{ fontFamily: T.font, fontSize: 11, color: T.text1, textTransform: "capitalize" }}>{tool}</span>
                <span style={{
                  fontFamily: T.font, fontSize: 10, fontWeight: 700,
                  color: stats.findings > 0 ? T.medium : T.accent,
                }}>{stats.findings ?? 0} findings</span>
              </div>
            ))}
          </div>
        </Card>

        {/* Quick navigation */}
        <Card>
          <CardHeader title="Schnellzugriff" />
          <div style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 8 }}>
            {[
              { label: "Alle Findings",    sub: `${openFindings.length} offen`,          path: "/findings", color: T.critical, Icon: AlertTriangle },
              { label: "Asset-Inventar",   sub: `${(assets||[]).length} Einträge`,       path: "/assets",   color: T.accent,   Icon: Globe         },
              { label: "MCP Exposure",     sub: `${(mcp||[]).length} Server`,            path: "/mcp",      color: (mcp||[]).length > 0 ? T.critical : T.text3, Icon: Cpu },
              { label: "Intelligence",     sub: "Hosting, Geo, DNS",                     path: "/intel",    color: T.low,      Icon: null           },
              { label: "Scan-Verlauf",     sub: `${(scans||[]).length} Scans`,           path: "/scans",    color: T.text2,    Icon: RefreshCw      },
            ].map(item => (
              <button key={item.path} onClick={() => navigate(item.path)} style={{
                display: "flex", alignItems: "center", gap: 10,
                background: T.bg3, border: `1px solid ${T.border}`,
                borderRadius: 6, padding: "9px 12px", cursor: "pointer", textAlign: "left",
                transition: "border-color 0.12s, background 0.12s",
              }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = item.color; e.currentTarget.style.background = T.bg4; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = T.border; e.currentTarget.style.background = T.bg3; }}
              >
                {item.Icon && <item.Icon size={14} color={item.color} />}
                <div style={{ flex: 1 }}>
                  <div style={{ fontFamily: T.fontSans, fontSize: 12, fontWeight: 500, color: T.text0 }}>{item.label}</div>
                  <div style={{ fontFamily: T.font, fontSize: 10, color: T.text3, marginTop: 1 }}>{item.sub}</div>
                </div>
                <span style={{ fontFamily: T.font, fontSize: 10, color: T.text3 }}>→</span>
              </button>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

function Row({ label, value, icon, valueColor }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        {icon}
        <span style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>{label}</span>
      </div>
      <span style={{ fontFamily: T.font, fontSize: 12, fontWeight: 600, color: valueColor || T.text1 }}>{value}</span>
    </div>
  );
}
