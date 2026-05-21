import { useState, Component } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "sonner";
import { getToken, clearToken, clearTenantId, getTenantId, saveTenantId } from "./api/client";
import { AppProvider } from "./context/AppContext";
import Shell                from "./components/layout/Shell";
import LoginPage            from "./pages/LoginPage";
import DashboardPage        from "./pages/DashboardPage";
import FindingsPage         from "./pages/FindingsPage";
import AssetsPage           from "./pages/AssetsPage";
import AssetsNewPage        from "./pages/AssetsNewPage";
import McpPage              from "./pages/McpPage";
import IntelPage            from "./pages/IntelPage";
import ScansPage            from "./pages/ScansPage";
import SettingsPage         from "./pages/SettingsPage";
import TargetsPage          from "./pages/TargetsPage";
import VulnerabilitiesPage  from "./pages/VulnerabilitiesPage";
import EmailIntelPage      from "./pages/EmailIntelPage";

// Ensure preference is set when running in v2
if (!localStorage.getItem("easm_ui")) {
  localStorage.setItem("easm_ui", "v2");
}

class ErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { err: null }; }
  static getDerivedStateFromError(err) { return { err }; }
  render() {
    if (!this.state.err) return this.props.children;
    return (
      <div style={{
        minHeight: "100vh", background: "#050810", display: "flex",
        alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 16, padding: 32,
        fontFamily: "'JetBrains Mono', monospace",
      }}>
        <div style={{ fontSize: 13, color: "#f43f5e", letterSpacing: "0.08em" }}>RENDER ERROR</div>
        <div style={{ fontSize: 10, color: "#94a3b8", maxWidth: 600, textAlign: "center", lineHeight: 1.8 }}>
          {String(this.state.err?.message || this.state.err)}
        </div>
        <button onClick={() => window.location.reload()} style={{
          background: "#22c55e", border: "none", borderRadius: 4, padding: "8px 20px",
          fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#052e16",
          cursor: "pointer", fontWeight: 700, marginTop: 8,
        }}>RELOAD</button>
      </div>
    );
  }
}

export default function App() {
  const [authed,   setAuthed]   = useState(!!getToken());
  const [tenantId, setTenantId] = useState(() => getTenantId());

  if (authed && !tenantId) {
    clearToken(); clearTenantId(); window.location.reload(); return null;
  }

  if (!authed) {
    return (
      <LoginPage onLogin={tid => { saveTenantId(tid); setTenantId(tid); setAuthed(true); }} />
    );
  }

  return (
    <ErrorBoundary>
      <AppProvider tenantId={tenantId}>
        <Toaster
          position="bottom-right"
          theme="dark"
          toastOptions={{ style: { fontFamily: "'JetBrains Mono', monospace", fontSize: 11 } }}
        />
        <BrowserRouter basename="/v2">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route element={<Shell />}>
              <Route path="/dashboard"       element={<DashboardPage />}       />
              <Route path="/findings"        element={<FindingsPage />}        />
              <Route path="/assets"          element={<AssetsPage />}          />
              <Route path="/assetsnew"       element={<AssetsNewPage />}       />
              <Route path="/mcp"             element={<McpPage />}             />
              <Route path="/intel"           element={<IntelPage />}           />
              <Route path="/intel/:tab"      element={<IntelPage />}           />
              <Route path="/scans"           element={<ScansPage />}           />
              <Route path="/targets"         element={<TargetsPage />}         />
              <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
              <Route path="/email-intel"     element={<EmailIntelPage />}      />
              <Route path="/settings"        element={<SettingsPage />}        />
              <Route path="*"          element={<Navigate to="/dashboard" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AppProvider>
    </ErrorBoundary>
  );
}
