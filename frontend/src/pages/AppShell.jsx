import { useState } from "react";
import { toast } from "sonner";
import { RefreshCw, LogOut, Settings, Shield, Sparkles } from "lucide-react";
import { T } from "../theme";
import { useApp } from "../context/AppContext";
import { apiFetch, clearToken, clearTenantId } from "../api/client";
import { Btn, Tag, SearchBar } from "../components/ui/index";
import SearchResults from "../components/SearchResults";
import OverviewTab from "./tabs/OverviewTab";
import FindingsTab from "./tabs/FindingsTab";
import AssetsTab from "./tabs/AssetsTab";
import MCPTab from "./tabs/MCPTab";
import IntelTab from "./tabs/IntelTab";
import ScansTab from "./tabs/ScansTab";
import ReportsTab from "./tabs/ReportsTab";
import AdminTab from "./tabs/AdminTab";

function buildTabs(findings, assets, mcp) {
  return [
    { id:"overview",  label:"Overview" },
    { id:"findings",  label:"Findings",     count: (findings||[]).filter(f=>f.status==="open").length },
    { id:"assets",    label:"Assets",       count: (assets||[]).length },
    { id:"mcp",       label:"MCP Exposure", count: (mcp||[]).length, alert: (mcp||[]).length > 0 },
    { id:"intel",     label:"Intelligence" },
    { id:"scans",     label:"Scans" },
    { id:"reports",   label:"Reports" },
  ];
}

function LoadingScreen() {
  return (
    <div style={{ minHeight: "100vh", background: T.bg0, display: "flex",
      alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 16 }}>
      <div style={{ width: 36, height: 36, borderRadius: 8,
        background: "linear-gradient(135deg, #22c55e, #15803d)",
        display: "flex", alignItems: "center", justifyContent: "center",
        animation: "pulse 1.5s ease-in-out infinite" }}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#050810" strokeWidth="2.5">
          <path d="M12 2L3 7v5c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V7L12 2z"/>
        </svg>
      </div>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#94a3b8",
        letterSpacing: "0.1em" }}>LADEN...</div>
    </div>
  );
}

export default function AppShell() {
  const { tenant, findings, assets, mcp, loading, error, triggerScan } = useApp();
  const [tab, setTab]                 = useState("overview");
  const [searchQuery, setSearchQuery] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [searchResult, setSearchResult] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const now = new Date().toISOString().slice(0,16).replace("T"," ") + " UTC";

  const tabs = buildTabs(findings, assets, mcp);

  const handleSearch = async (q) => {
    if (!q.trim()) { setSearchResult(null); setSearchQuery(""); return; }
    setSearchQuery(q);
    setSearchInput(q);
    setSearchLoading(true);
    setSearchResult(null);
    try {
      const params = new URLSearchParams({ q, scope: "all", limit: 50 });
      const res = await apiFetch(`/search?${params}`);
      setSearchResult(res);
    } catch(e) {
      setSearchResult({ error: e.message, results: { findings:[], assets:[] },
        total: { findings:0, assets:0 }, took_ms: 0 });
    } finally {
      setSearchLoading(false);
    }
  };

  if (loading) return <LoadingScreen />;

  const scoreColor = tenant.score >= 70 ? T.accent : tenant.score >= 40 ? T.medium : T.critical;
  const lastScanStr = tenant.last_scan
    ? new Date(tenant.last_scan).toLocaleString("de-DE", { dateStyle:"short", timeStyle:"short" })
    : "—";
  const nextScanStr = tenant.next_scan
    ? new Date(tenant.next_scan).toLocaleString("de-DE", { dateStyle:"short", timeStyle:"short" })
    : "—";

  return (
    <div style={{ minHeight: "100vh", background: T.bg0, color: T.text0, fontFamily: T.fontSans }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: ${T.bg1}; }
        ::-webkit-scrollbar-thumb { background: ${T.border2}; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: ${T.text3}; }
        ::placeholder { color: ${T.text3}; }
        input[type=checkbox] { accent-color: ${T.accent}; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:none} }
        @keyframes shimmer { 0%{background-position:200% 0} 100%{background-position:-200% 0} }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
      `}</style>

      {/* Top Navigation */}
      <div style={{ background: T.bg1, borderBottom: `1px solid ${T.border}`,
        position: "sticky", top: 0, zIndex: 100 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 0,
          padding: "0 24px", height: 48, borderBottom: `1px solid ${T.border}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginRight: 32 }}>
            <div style={{ width: 28, height: 28, borderRadius: 6,
              background: "linear-gradient(135deg, #22c55e, #15803d)",
              display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Shield size={16} color={T.bg0} strokeWidth={2.5} />
            </div>
            <div>
              <div style={{ fontFamily: T.font, fontSize: 13, fontWeight: 700, color: T.text0, letterSpacing: "0.02em" }}>EASM</div>
              <div style={{ fontFamily: T.font, fontSize: 8, color: T.text3, letterSpacing: "0.06em" }}>MSSP PLATFORM</div>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 8,
            background: T.bg2, border: `1px solid ${T.border}`,
            borderRadius: 4, padding: "5px 12px", marginRight: 24 }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: T.accent, animation: "pulse 2s infinite" }} />
            <span style={{ fontFamily: T.font, fontSize: 11, color: T.accent, fontWeight: 600 }}>
              {tenant.domain || "—"}
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <Tag label={`Score: ${tenant.score}`} color={scoreColor} bg={`${scoreColor}12`} border={`${scoreColor}30`} />
            <Tag label={`Grade ${tenant.grade}`} color={scoreColor} bg={`${scoreColor}12`} border={`${scoreColor}30`} />
            {error && <Tag label="API Error" color={T.medium} bg={T.mediumBg} border={T.mediumBorder} />}
          </div>

          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>
              Letzter Scan: <span style={{ color: T.text2 }}>{lastScanStr}</span>
            </div>
            <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>
              Nächster: <span style={{ color: T.accent }}>{nextScanStr}</span>
            </div>
            <Btn onClick={() => {
              triggerScan("full")
                .then(() => toast.success("Scan gestartet", { description: "Full-Pipeline läuft im Hintergrund." }))
                .catch(e => toast.error("Scan fehlgeschlagen", { description: e.message }));
            }} variant="primary" size="sm">
              <RefreshCw size={10} />SCAN NOW
            </Btn>
            <button
              onClick={() => { localStorage.setItem("easm_ui", "v2"); window.location.replace("/v2/"); }}
              title="Neues UI ausprobieren"
              style={{ background: "transparent", border: `1px solid #22c55e40`,
                borderRadius: 4, padding: "4px 10px", fontFamily: T.font, fontSize: 9,
                color: "#22c55e", cursor: "pointer", display: "flex", alignItems: "center", gap: 5 }}>
              <Sparkles size={9} />NEW UI
            </button>
            <button onClick={() => { clearToken(); clearTenantId(); window.location.reload(); }}
              style={{ background: "transparent", border: `1px solid ${T.border}`,
                borderRadius: 4, padding: "4px 10px", fontFamily: T.font, fontSize: 9,
                color: T.text3, cursor: "pointer", display: "flex", alignItems: "center", gap: 5 }}>
              <LogOut size={9} />Logout
            </button>
          </div>
        </div>

        <div style={{ padding: "10px 24px" }}>
          <SearchBar onSearch={handleSearch} liveQuery={searchInput} onInputChange={setSearchInput} />
        </div>
      </div>

      {/* Tab navigation */}
      <div style={{ background: T.bg1, borderBottom: `1px solid ${T.border}`,
        display: "flex", gap: 0, padding: "0 24px",
        position: "sticky", top: 118, zIndex: 99 }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => { setTab(t.id); setSearchResult(null); setSearchInput(""); }}
            style={{ padding: "12px 18px", background: "transparent", border: "none",
              borderBottom: `2px solid ${tab === t.id ? T.accent : "transparent"}`,
              fontFamily: T.fontSans, fontSize: 12, fontWeight: tab === t.id ? 600 : 400,
              color: tab === t.id ? T.accent : T.text1, cursor: "pointer",
              display: "flex", alignItems: "center", gap: 7, transition: "color 0.15s", marginBottom: -1 }}>
            {t.label}
            {t.count != null && (
              <span style={{ fontFamily: T.font, fontSize: 9, fontWeight: 700,
                background: t.alert ? `${T.critical}20` : T.bg3,
                color: t.alert ? T.red : T.text2,
                border: `1px solid ${t.alert ? `${T.critical}40` : T.border}`,
                padding: "1px 6px", borderRadius: 999 }}>{t.count}</span>
            )}
          </button>
        ))}
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 0 }}>
          <button onClick={() => setTab("admin")} style={{ padding: "12px 18px",
            background: "transparent", border: "none",
            borderBottom: `2px solid ${tab === "admin" ? T.accent : "transparent"}`,
            fontFamily: T.fontSans, fontSize: 12, fontWeight: tab === "admin" ? 600 : 400,
            color: tab === "admin" ? T.accent : T.text2, cursor: "pointer",
            display: "flex", alignItems: "center", gap: 6, marginBottom: -1 }}>
            <Settings size={12} />Settings
          </button>
          <div style={{ width: 1, height: 20, background: T.border, margin: "0 12px" }}/>
          <span style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>{now}</span>
        </div>
      </div>

      {/* Main content */}
      <main style={{ padding: "24px", maxWidth: 1600, margin: "0 auto" }}>
        {(searchResult !== null || searchLoading) ? (
          <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 6, overflow: "hidden" }}>
            <SearchResults
              result={searchResult}
              query={searchQuery}
              loading={searchLoading}
              onClear={() => { setSearchResult(null); setSearchQuery(""); setSearchInput(""); }}
            />
          </div>
        ) : (
          <>
            {tab === "overview" && <OverviewTab setTab={setTab} />}
            {tab === "findings" && <FindingsTab />}
            {tab === "assets"   && <AssetsTab />}
            {tab === "mcp"      && <MCPTab />}
            {tab === "intel"    && <IntelTab />}
            {tab === "scans"    && <ScansTab />}
            {tab === "reports"  && <ReportsTab />}
            {tab === "admin"    && <AdminTab />}
          </>
        )}
      </main>
    </div>
  );
}
