import { useState, Component } from "react";
import { Toaster } from "sonner";
import { getToken, clearToken, clearTenantId, getTenantId, saveTenantId } from "./api/client";
import { AppProvider } from "./context/AppContext";
import LoginPage from "./pages/LoginPage";
import AppShell from "./pages/AppShell";

class ErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { err: null }; }
  static getDerivedStateFromError(err) { return { err }; }
  render() {
    if (!this.state.err) return this.props.children;
    return (
      <div style={{ minHeight:"100vh", background:"#050810", display:"flex", alignItems:"center",
        justifyContent:"center", flexDirection:"column", gap:16, padding:32 }}>
        <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:13, color:"#f43f5e",
          letterSpacing:"0.08em" }}>RENDER ERROR</div>
        <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:10, color:"#94a3b8",
          maxWidth:600, textAlign:"center", lineHeight:1.8 }}>
          {String(this.state.err?.message || this.state.err)}
        </div>
        <button onClick={() => window.location.reload()}
          style={{ background:"#22c55e", border:"none", borderRadius:4, padding:"8px 20px",
            fontFamily:"'JetBrains Mono',monospace", fontSize:10, color:"#050810",
            cursor:"pointer", fontWeight:700, letterSpacing:"0.06em", marginTop:8 }}>
          RELOAD
        </button>
      </div>
    );
  }
}

// Redirect to v2 before any React renders if the user prefers it.
if (localStorage.getItem("easm_ui") === "v2") {
  window.location.replace("/v2/");
}

export default function App() {
  const [authed,   setAuthed]   = useState(!!getToken());
  const [tenantId, setTenantId] = useState(() => getTenantId());

  if (authed && !tenantId) {
    clearToken();
    clearTenantId();
    window.location.reload();
    return null;
  }

  if (!authed) {
    return (
      <LoginPage onLogin={(tid) => { saveTenantId(tid); setTenantId(tid); setAuthed(true); }} />
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
        <AppShell />
      </AppProvider>
    </ErrorBoundary>
  );
}
