import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

function Placeholder() {
  return (
    <div style={{
      minHeight: "100vh",
      background: "#0a0f1e",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      flexDirection: "column",
      gap: 24,
      fontFamily: "system-ui, -apple-system, sans-serif",
    }}>
      <div style={{
        background: "linear-gradient(135deg, #22c55e, #15803d)",
        borderRadius: 12,
        width: 56,
        height: 56,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontSize: 28,
      }}>
        🛡
      </div>
      <div style={{ textAlign: "center", maxWidth: 400 }}>
        <div style={{ fontSize: 22, fontWeight: 700, color: "#f1f5f9", marginBottom: 8 }}>
          EASM Platform v2
        </div>
        <div style={{ fontSize: 14, color: "#64748b", lineHeight: 1.6 }}>
          Das neue UI befindet sich in der Entwicklung.
          Diese Seite wird durch die vollständige Neuentwicklung ersetzt.
        </div>
      </div>
      <button
        onClick={() => {
          localStorage.setItem("easm_ui", "classic");
          window.location.replace("/");
        }}
        style={{
          background: "transparent",
          border: "1px solid #334155",
          borderRadius: 6,
          padding: "8px 20px",
          color: "#94a3b8",
          fontSize: 13,
          cursor: "pointer",
          transition: "color 0.15s, border-color 0.15s",
        }}
        onMouseEnter={e => { e.target.style.color = "#f1f5f9"; e.target.style.borderColor = "#64748b"; }}
        onMouseLeave={e => { e.target.style.color = "#94a3b8"; e.target.style.borderColor = "#334155"; }}
      >
        ← Zurück zur Classic UI
      </button>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter basename="/v2">
      <Routes>
        <Route path="/" element={<Placeholder />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
