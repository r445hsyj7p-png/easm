import { useState } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  LayoutDashboard, AlertTriangle, Globe, Cpu, Radar,
  RefreshCw, Settings, LogOut, Shield, ChevronLeft,
  ChevronRight, ArrowLeft, Zap, Sun, Moon,
} from "lucide-react";
import { toast } from "sonner";
import { T, alpha } from "../../theme";
import { useApp } from "../../context/AppContext";
import { clearToken, clearTenantId } from "../../api/client";
import { useTheme } from "../../hooks/useTheme";
import { Spinner } from "../ui/index";

const NAV_ITEMS = [
  { path: "/dashboard", label: "Dashboard",    Icon: LayoutDashboard                      },
  { path: "/findings",  label: "Findings",     Icon: AlertTriangle, countKey: "findings" },
  { path: "/assets",    label: "Assets",       Icon: Globe,         countKey: "assets"   },
  { path: "/mcp",       label: "MCP Exposure", Icon: Cpu,           countKey: "mcp", alert: true },
  { path: "/intel",     label: "Intelligence", Icon: Radar                                },
  { path: "/scans",     label: "Scans",        Icon: RefreshCw                            },
];

function NavItem({ item, active, collapsed, counts }) {
  const navigate = useNavigate();
  const count    = item.countKey ? (counts[item.countKey] ?? 0) : null;
  const hasAlert = item.alert && count > 0;

  return (
    <button
      onClick={() => navigate(item.path)}
      title={collapsed ? item.label : undefined}
      style={{
        display: "flex", alignItems: "center", gap: 10, width: "100%",
        padding: collapsed ? "9px 0" : "9px 12px",
        justifyContent: collapsed ? "center" : "flex-start",
        background: active ? alpha(T.accent, 7) : "transparent",
        border: "none",
        borderLeft: `2px solid ${active ? T.accent : "transparent"}`,
        borderRadius: 6,
        fontFamily: T.fontSans, fontSize: 13, fontWeight: active ? 600 : 400,
        color: active ? T.accent : T.text2, cursor: "pointer",
        transition: "all 0.12s", marginBottom: 2,
      }}
      onMouseEnter={e => { if (!active) { e.currentTarget.style.background = T.bg3; e.currentTarget.style.color = T.text1; }}}
      onMouseLeave={e => { if (!active) { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = T.text2; }}}
    >
      <item.Icon size={16} style={{ flexShrink: 0 }} />
      {!collapsed && (
        <>
          <span style={{ flex: 1, textAlign: "left" }}>{item.label}</span>
          {count !== null && count > 0 && (
            <span style={{
              fontFamily: T.font, fontSize: 9, fontWeight: 700,
              background: hasAlert ? alpha(T.critical, 13) : T.bg4,
              color:      hasAlert ? T.critical : T.text3,
              border:    `1px solid ${hasAlert ? alpha(T.critical, 25) : T.border}`,
              padding: "1px 7px", borderRadius: 999, flexShrink: 0,
            }}>{count}</span>
          )}
        </>
      )}
    </button>
  );
}

export default function Shell() {
  const [collapsed, setCollapsed] = useState(false);
  const location  = useLocation();
  const { theme, toggle: toggleTheme, isDark } = useTheme();
  const { tenant, findings, assets, mcp, loading, triggerScan } = useApp();

  const counts = {
    findings: (findings || []).filter(f => f.status === "open").length,
    assets:   (assets || []).length,
    mcp:      (mcp || []).length,
  };

  const scoreColor = (tenant.score || 0) >= 70 ? T.accent
    : (tenant.score || 0) >= 40 ? T.medium : T.critical;

  const handleScan = async () => {
    try {
      await triggerScan("full");
      toast.success("Scan gestartet", { description: "Full-Pipeline läuft im Hintergrund." });
    } catch (e) {
      toast.error("Scan fehlgeschlagen", { description: e.message });
    }
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: T.bg0 }}>
      {/* ── Sidebar ── */}
      <aside style={{
        width: collapsed ? 56 : 232, flexShrink: 0,
        background: T.bg1, borderRight: `1px solid ${T.border}`,
        display: "flex", flexDirection: "column",
        transition: "width 0.2s ease", overflow: "hidden",
        position: "sticky", top: 0, height: "100vh",
      }}>
        {/* Logo */}
        <div style={{
          height: 56, display: "flex", alignItems: "center",
          padding: collapsed ? "0" : "0 16px",
          justifyContent: collapsed ? "center" : "flex-start",
          gap: 10, borderBottom: `1px solid ${T.border}`, flexShrink: 0,
        }}>
          <div style={{
            width: 28, height: 28, borderRadius: 6, flexShrink: 0,
            background: "linear-gradient(135deg, var(--accent), var(--accent-dim))",
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <Shield size={15} color="var(--background)" strokeWidth={2.5} />
          </div>
          {!collapsed && (
            <div>
              <div style={{ fontFamily: T.font, fontSize: 13, fontWeight: 700, color: T.text0 }}>EASM</div>
              <div style={{ fontFamily: T.font, fontSize: 8, color: T.text3, letterSpacing: "0.06em" }}>v2 · MSSP PLATFORM</div>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: collapsed ? "12px 4px" : "12px 0 12px 12px", overflow: "auto" }}>
          {NAV_ITEMS.map(item => (
            <NavItem
              key={item.path}
              item={item}
              active={location.pathname === item.path}
              collapsed={collapsed}
              counts={counts}
            />
          ))}
        </nav>

        {/* Bottom: settings + theme toggle + collapse */}
        <div style={{
          padding: collapsed ? "12px 4px" : "12px 0 12px 12px",
          borderTop: `1px solid ${T.border}`, flexShrink: 0,
        }}>
          <NavItem
            item={{ path: "/settings", label: "Settings", Icon: Settings }}
            active={location.pathname === "/settings"}
            collapsed={collapsed}
            counts={counts}
          />

          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            title={isDark ? "Light Mode" : "Dark Mode"}
            style={{
              display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
              width: collapsed ? 36 : "calc(100% - 12px)", margin: collapsed ? "4px auto 0" : "4px 12px 0 0",
              padding: "7px", background: "transparent", border: `1px solid ${T.border}`,
              borderRadius: 6, color: T.text3, cursor: "pointer", transition: "all 0.12s",
              fontFamily: T.fontSans, fontSize: 11,
            }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = T.border2; e.currentTarget.style.color = T.text2; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = T.border; e.currentTarget.style.color = T.text3; }}
          >
            {isDark ? <Sun size={13} /> : <Moon size={13} />}
            {!collapsed && <span>{isDark ? "Light" : "Dark"}</span>}
          </button>

          <button
            onClick={() => setCollapsed(c => !c)}
            title={collapsed ? "Ausklappen" : "Einklappen"}
            style={{
              display: "flex", alignItems: "center", justifyContent: "center",
              width: collapsed ? 36 : "calc(100% - 12px)", margin: collapsed ? "4px auto 0" : "4px 12px 0 0",
              padding: 7, background: "transparent", border: `1px solid ${T.border}`,
              borderRadius: 6, color: T.text3, cursor: "pointer", transition: "all 0.12s",
            }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = T.border2; e.currentTarget.style.color = T.text2; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = T.border; e.currentTarget.style.color = T.text3; }}
          >
            {collapsed ? <ChevronRight size={13} /> : <ChevronLeft size={13} />}
          </button>
        </div>
      </aside>

      {/* ── Main column ── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, overflow: "hidden" }}>
        {/* Top bar */}
        <header style={{
          height: 56, display: "flex", alignItems: "center",
          padding: "0 24px", gap: 10,
          background: T.bg1, borderBottom: `1px solid ${T.border}`,
          position: "sticky", top: 0, zIndex: 50, flexShrink: 0,
        }}>
          {/* Tenant domain */}
          <div style={{
            display: "flex", alignItems: "center", gap: 8,
            background: T.bg2, border: `1px solid ${T.border}`,
            borderRadius: 6, padding: "5px 12px",
          }}>
            <div style={{
              width: 7, height: 7, borderRadius: "50%",
              background: T.accent, animation: "pulse 2s infinite",
            }} />
            <span style={{ fontFamily: T.font, fontSize: 12, color: T.accent, fontWeight: 600 }}>
              {tenant.domain || "—"}
            </span>
          </div>

          {/* Score badge */}
          <div style={{
            background: alpha(scoreColor, 7),
            border: `1px solid ${alpha(scoreColor, 19)}`,
            borderRadius: 6, padding: "5px 10px",
            fontFamily: T.font, fontSize: 11, color: scoreColor, fontWeight: 700,
          }}>
            Score {tenant.score ?? "—"} &nbsp;·&nbsp; Grade {tenant.grade ?? "?"}
          </div>

          {loading && <Spinner size={16} />}
          <div style={{ flex: 1 }} />

          {/* Scan */}
          <button onClick={handleScan} style={{
            display: "flex", alignItems: "center", gap: 6,
            background: T.accent, border: "none", borderRadius: 6,
            padding: "7px 14px", fontFamily: T.font, fontSize: 11, fontWeight: 700,
            color: "var(--background)", cursor: "pointer", letterSpacing: "0.04em",
          }}>
            <Zap size={12} />SCAN NOW
          </button>

          {/* Switch to Classic */}
          <button
            onClick={() => { localStorage.setItem("easm_ui", "classic"); window.location.replace("/"); }}
            style={{
              display: "flex", alignItems: "center", gap: 5,
              background: "transparent", border: `1px solid ${T.border}`,
              borderRadius: 6, padding: "6px 12px", fontFamily: T.font, fontSize: 10,
              color: T.text3, cursor: "pointer", transition: "color 0.12s, border-color 0.12s",
            }}
            onMouseEnter={e => { e.currentTarget.style.color = T.text1; e.currentTarget.style.borderColor = T.border2; }}
            onMouseLeave={e => { e.currentTarget.style.color = T.text3; e.currentTarget.style.borderColor = T.border; }}
          >
            <ArrowLeft size={10} />Classic UI
          </button>

          {/* Logout */}
          <button
            onClick={() => { clearToken(); clearTenantId(); window.location.reload(); }}
            style={{
              display: "flex", alignItems: "center", gap: 5,
              background: "transparent", border: `1px solid ${T.border}`,
              borderRadius: 6, padding: "6px 12px", fontFamily: T.font, fontSize: 10,
              color: T.text3, cursor: "pointer", transition: "color 0.12s, border-color 0.12s",
            }}
            onMouseEnter={e => { e.currentTarget.style.color = T.critical; e.currentTarget.style.borderColor = T.criticalBorder; }}
            onMouseLeave={e => { e.currentTarget.style.color = T.text3; e.currentTarget.style.borderColor = T.border; }}
          >
            <LogOut size={10} />Logout
          </button>
        </header>

        {/* Page content */}
        <main style={{ flex: 1, overflow: "auto", padding: 24, animation: "fadeIn 0.15s ease" }}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
