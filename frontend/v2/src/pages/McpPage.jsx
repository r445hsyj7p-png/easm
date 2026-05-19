import { useState } from "react";
import { Cpu, AlertTriangle } from "lucide-react";
import { T, SEV } from "../theme";
import { KpiCard, Card, CardHeader, TH, TD, SevBadge, EmptyState, PageLoading, SearchInput } from "../components/ui/index";
import { useApp } from "../context/AppContext";

export default function McpPage() {
  const { mcp, loading } = useApp();
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState(null);

  if (loading) return <PageLoading />;

  const serverList = mcp || [];

  const filtered = serverList.filter(s => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      (s.host || s.url || "").toLowerCase().includes(q) ||
      (s.server_name || s.name || "").toLowerCase().includes(q) ||
      (s.type || "").toLowerCase().includes(q)
    );
  });

  const riskyCount = serverList.filter(s =>
    (s.risk || "").toUpperCase() === "CRITICAL" || (s.risk || "").toUpperCase() === "HIGH"
  ).length;
  const noAuthCount = serverList.filter(s => !s.auth_required && s.auth_required !== undefined).length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Alert banner */}
      {serverList.length > 0 && (
        <div style={{
          background: T.criticalBg, border: `1px solid ${T.criticalBorder}`,
          borderLeft: `3px solid ${T.critical}`,
          borderRadius: 6, padding: "14px 18px",
          display: "flex", alignItems: "flex-start", gap: 12,
        }}>
          <AlertTriangle size={18} color={T.critical} style={{ flexShrink: 0, marginTop: 1 }} />
          <div>
            <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.critical }}>
              {serverList.length} MCP-Server exponiert
            </div>
            <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text2, marginTop: 4, lineHeight: 1.5 }}>
              MCP (Model Context Protocol) Server sind AI-Agent-Endpunkte, die ohne angemessene
              Zugangskontrolle ein erhebliches Sicherheitsrisiko darstellen. Exponierte Server
              können von Angreifern für Prompt-Injection oder unbefugten Datenzugriff missbraucht werden.
            </div>
          </div>
        </div>
      )}

      {/* KPIs */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
        <KpiCard label="MCP Server" value={serverList.length} icon={Cpu} color={serverList.length > 0 ? T.critical : T.text2} />
        <KpiCard label="Kritisch / Hoch" value={riskyCount} color={riskyCount > 0 ? T.critical : T.text2} />
        <KpiCard label="Ohne Auth" value={noAuthCount} color={noAuthCount > 0 ? T.high : T.text2} sub="Kein Auth-Schutz erkannt" />
        <KpiCard label="Domains" value={new Set(serverList.map(s => (s.host || s.url || "").split(":")[0])).size} />
      </div>

      {/* Table + detail */}
      <div style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
        <Card style={{ flex: 1 }}>
          <CardHeader title="MCP Server" sub={`${filtered.length} Einträge`} />

          <div style={{ padding: "10px 16px", borderBottom: `1px solid ${T.border}` }}>
            <SearchInput value={search} onChange={setSearch} placeholder="Host, Name, Typ…" width={240} />
          </div>

          {serverList.length === 0 ? (
            <EmptyState
              icon={Cpu}
              title="Keine MCP Server gefunden"
              sub="Im letzten Scan wurden keine exponierten MCP-Endpunkte entdeckt."
            />
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    <TH>Host / URL</TH>
                    <TH>Server-Name</TH>
                    <TH>Typ</TH>
                    <TH>Auth</TH>
                    <TH>Protokolle</TH>
                    <TH>Risiko</TH>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((s, i) => {
                    const risk = (s.risk || "INFO").toUpperCase();
                    const sevStyle = SEV[risk] || SEV.INFO;
                    const isSelected = selected?.id === s.id || (selected && selected === s);
                    return (
                      <tr key={i}
                        onClick={() => setSelected(isSelected ? null : s)}
                        style={{
                          cursor: "pointer",
                          background: isSelected ? T.bg3 : "transparent",
                          transition: "background 0.1s",
                        }}
                        onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = T.bg3; }}
                        onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = "transparent"; }}
                      >
                        <TD style={{ fontFamily: T.font, fontSize: 11, color: T.low }}>
                          {s.host || s.url || "—"}
                        </TD>
                        <TD>
                          <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text0 }}>
                            {s.server_name || s.name || "—"}
                          </div>
                          {s.version && (
                            <div style={{ fontFamily: T.font, fontSize: 10, color: T.text3 }}>v{s.version}</div>
                          )}
                        </TD>
                        <TD>
                          {s.type ? (
                            <span style={{
                              fontFamily: T.font, fontSize: 10, color: T.text2,
                              background: T.bg4, border: `1px solid ${T.border}`,
                              padding: "1px 7px", borderRadius: 3,
                            }}>{s.type}</span>
                          ) : "—"}
                        </TD>
                        <TD>
                          {s.auth_required === false ? (
                            <span style={{
                              fontFamily: T.font, fontSize: 10, fontWeight: 700,
                              color: T.critical, background: T.criticalBg,
                              border: `1px solid ${T.criticalBorder}`,
                              padding: "1px 7px", borderRadius: 3,
                            }}>KEINE AUTH</span>
                          ) : s.auth_required === true ? (
                            <span style={{
                              fontFamily: T.font, fontSize: 10, color: T.accent,
                              background: T.accent3, border: `1px solid ${T.accent}30`,
                              padding: "1px 7px", borderRadius: 3,
                            }}>AUTH</span>
                          ) : (
                            <span style={{ fontFamily: T.font, fontSize: 10, color: T.text4 }}>—</span>
                          )}
                        </TD>
                        <TD>
                          <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                            {(s.protocols || s.transports || []).map((p, j) => (
                              <span key={j} style={{
                                fontFamily: T.font, fontSize: 9, color: T.text2,
                                background: T.bg4, border: `1px solid ${T.border}`,
                                padding: "0 5px", borderRadius: 3,
                              }}>{p}</span>
                            ))}
                            {!(s.protocols || s.transports || []).length && (
                              <span style={{ fontFamily: T.font, fontSize: 10, color: T.text4 }}>—</span>
                            )}
                          </div>
                        </TD>
                        <TD><SevBadge sev={risk} small /></TD>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {/* Detail panel */}
        {selected && (
          <div style={{
            width: 340, flexShrink: 0,
            background: T.bg2, border: `1px solid ${T.border}`,
            borderTop: `2px solid ${T.critical}`,
            borderRadius: 8, padding: 0, overflow: "hidden",
            position: "sticky", top: 0,
            animation: "slideIn 0.15s ease",
          }}>
            <div style={{
              display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "12px 16px", borderBottom: `1px solid ${T.border}`, background: T.bg3,
            }}>
              <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0 }}>
                {selected.server_name || selected.name || "MCP Server"}
              </div>
              <button onClick={() => setSelected(null)} style={{
                background: "transparent", border: "none", color: T.text3, cursor: "pointer",
              }}>✕</button>
            </div>
            <div style={{ padding: "14px 16px", display: "flex", flexDirection: "column", gap: 12 }}>
              <DetailRow label="Host"       value={selected.host || selected.url || "—"} mono />
              <DetailRow label="Typ"        value={selected.type || "—"} />
              <DetailRow label="Version"    value={selected.version || "—"} mono />
              <DetailRow label="Auth"       value={selected.auth_required === false ? "Keine Authentifizierung!" : selected.auth_required === true ? "Authentifiziert" : "Unbekannt"} />
              <DetailRow label="Endpunkte"  value={(selected.endpoints || []).join(", ") || "—"} mono />
              <DetailRow label="Protokolle" value={(selected.protocols || selected.transports || []).join(", ") || "—"} />
              {selected.tools?.length > 0 && (
                <div>
                  <div style={{ fontFamily: T.font, fontSize: 9, color: T.text4, letterSpacing: "0.08em", marginBottom: 6 }}>VERFÜGBARE TOOLS</div>
                  {selected.tools.map((t, i) => (
                    <div key={i} style={{
                      fontFamily: T.font, fontSize: 11, color: T.text1,
                      padding: "5px 8px", background: T.bg3, borderRadius: 4, marginBottom: 4,
                    }}>{typeof t === "string" ? t : t.name || JSON.stringify(t)}</div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function DetailRow({ label, value, mono }) {
  return (
    <div>
      <div style={{ fontFamily: T.font, fontSize: 9, color: T.text4, letterSpacing: "0.08em", marginBottom: 3 }}>{label.toUpperCase()}</div>
      <div style={{ fontFamily: mono ? T.font : T.fontSans, fontSize: mono ? 10 : 12, color: T.text1, wordBreak: "break-all" }}>{value}</div>
    </div>
  );
}
