import { useState, useEffect } from "react";
import { Shield } from "lucide-react";
import { T } from "../theme";
import { saveToken, saveTenantId } from "../api/client";

const inp = {
  width: "100%", background: T.bg3, border: `1px solid ${T.border}`,
  borderRadius: 6, padding: "10px 14px", fontFamily: T.fontSans, fontSize: 13,
  color: T.text0, outline: "none",
};
const lbl = {
  fontFamily: T.fontSans, fontSize: 11, color: T.text3,
  letterSpacing: "0.04em", display: "block", marginBottom: 6, textTransform: "uppercase",
};

export default function LoginPage({ onLogin }) {
  const [mode,       setMode]      = useState(null);
  const [email,      setEmail]     = useState("");
  const [password,   setPassword]  = useState("");
  const [confirmPw,  setConfirmPw] = useState("");
  const [name,       setName]      = useState("");
  const [loading,    setLoading]   = useState(false);
  const [error,      setError]     = useState("");
  const [pwStrength, setPwStr]     = useState(0);

  useEffect(() => {
    fetch("/api/v1/auth/status")
      .then(r => r.json())
      .then(d => setMode(d.setup_required ? "setup" : "login"))
      .catch(() => setMode("login"));
  }, []);

  useEffect(() => {
    if (!password) { setPwStr(0); return; }
    let s = 0;
    if (password.length >= 8)  s++;
    if (password.length >= 12) s++;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) s++;
    if (/[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password)) s++;
    setPwStr(s);
  }, [password]);

  const pwColor = ["", T.critical, T.high, T.medium, T.accent][pwStrength];
  const pwLabel = ["", "Schwach", "Mäßig", "Gut", "Stark"][pwStrength];

  const doSetup = async () => {
    setError("");
    if (!name.trim())           return setError("Bitte Namen eingeben.");
    if (!email.trim())          return setError("Bitte E-Mail eingeben.");
    if (password.length < 8)    return setError("Passwort muss mindestens 8 Zeichen haben.");
    if (password !== confirmPw) return setError("Passwörter stimmen nicht überein.");
    setLoading(true);
    try {
      const res = await fetch("/api/v1/auth/setup", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, name }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error(Array.isArray(e.detail) ? e.detail.map(d => d.msg).join(", ") : (e.detail || `Fehler ${res.status}`));
      }
      const { access_token, tenant_id } = await res.json();
      if (!tenant_id) throw new Error("Keine tenant_id in der Antwort.");
      saveToken(access_token); saveTenantId(tenant_id); onLogin(tenant_id);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const doLogin = async () => {
    setError("");
    if (!email.trim() || !password) return setError("Bitte E-Mail und Passwort eingeben.");
    setLoading(true);
    try {
      const res = await fetch("/api/v1/auth/login", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error(Array.isArray(e.detail) ? e.detail.map(d => d.msg).join(", ") : (e.detail || `Fehler ${res.status}`));
      }
      const { access_token, tenant_id } = await res.json();
      if (!tenant_id) throw new Error("Keine tenant_id in der Antwort.");
      saveToken(access_token); saveTenantId(tenant_id); onLogin(tenant_id);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const onKey = e => { if (e.key === "Enter") mode === "setup" ? doSetup() : doLogin(); };

  return (
    <div style={{
      minHeight: "100vh", background: T.bg0,
      display: "flex", alignItems: "center", justifyContent: "center",
      fontFamily: T.fontSans,
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap');
        *, *::before, *::after { box-sizing: border-box; }
        input:focus { border-color: ${T.accent} !important; box-shadow: 0 0 0 2px ${T.accent}20; }
        @keyframes fadeIn { from{opacity:0;transform:translateY(12px)} to{opacity:1;transform:none} }
      `}</style>

      <div style={{
        background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 12,
        padding: "40px 44px", width: 420,
        boxShadow: "0 32px 80px rgba(0,0,0,0.6)",
        animation: "fadeIn 0.25s ease",
      }}>
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 32 }}>
          <div style={{
            width: 40, height: 40, borderRadius: 10, flexShrink: 0,
            background: "linear-gradient(135deg, #22c55e, #15803d)",
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <Shield size={22} color={T.bg0} strokeWidth={2.5} />
          </div>
          <div>
            <div style={{ fontFamily: T.fontSans, fontSize: 18, fontWeight: 700, color: T.text0 }}>EASM Platform</div>
            <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, letterSpacing: "0.08em" }}>MSSP · EXTERNAL ATTACK SURFACE · v2</div>
          </div>
        </div>

        {mode === null && (
          <div style={{ textAlign: "center", padding: "32px 0", color: T.text3, fontFamily: T.font, fontSize: 11 }}>
            Verbinde mit Backend…
          </div>
        )}

        {mode === "setup" && (
          <>
            <div style={{
              display: "flex", gap: 10, alignItems: "flex-start", marginBottom: 24,
              padding: "12px 14px", background: `${T.accent}10`,
              border: `1px solid ${T.accent}30`, borderRadius: 6,
            }}>
              <div style={{ marginTop: 1 }}>
                <div style={{ fontFamily: T.fontSans, fontSize: 12, fontWeight: 600, color: T.accent }}>Ersteinrichtung</div>
                <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text2, marginTop: 2 }}>Lege deinen Admin-Account an.</div>
              </div>
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={lbl}>Vollständiger Name</label>
              <input value={name} onChange={e=>setName(e.target.value)} onKeyDown={onKey} placeholder="Max Mustermann" style={inp} autoFocus />
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={lbl}>E-Mail</label>
              <input type="email" value={email} onChange={e=>setEmail(e.target.value)} onKeyDown={onKey} placeholder="admin@beispiel.de" style={inp} />
            </div>
            <div style={{ marginBottom: password ? 8 : 16 }}>
              <label style={lbl}>Passwort</label>
              <input type="password" value={password} onChange={e=>setPassword(e.target.value)} onKeyDown={onKey} placeholder="Mindestens 8 Zeichen" style={inp} />
            </div>
            {password && (
              <div style={{ marginBottom: 16 }}>
                <div style={{ height: 3, background: T.bg4, borderRadius: 2, overflow: "hidden", marginBottom: 5 }}>
                  <div style={{ height: "100%", width: `${pwStrength*25}%`, background: pwColor, borderRadius: 2, transition: "all 0.2s" }} />
                </div>
                <div style={{ fontFamily: T.font, fontSize: 10, color: pwColor }}>{pwLabel}</div>
              </div>
            )}
            <div style={{ marginBottom: 24 }}>
              <label style={lbl}>Passwort bestätigen</label>
              <input type="password" value={confirmPw} onChange={e=>setConfirmPw(e.target.value)} onKeyDown={onKey}
                style={{...inp, borderColor: confirmPw && confirmPw !== password ? T.critical : confirmPw && confirmPw === password ? T.accent : T.border}} />
              {confirmPw && confirmPw === password && (
                <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.accent, marginTop: 5 }}>✓ Passwörter stimmen überein</div>
              )}
            </div>
            {error && <ErrorBox msg={error} />}
            <SubmitBtn label={loading ? "Einrichten…" : "Account erstellen"} loading={loading} onClick={doSetup} />
          </>
        )}

        {mode === "login" && (
          <>
            <div style={{ marginBottom: 18 }}>
              <label style={lbl}>E-Mail</label>
              <input type="email" value={email} onChange={e=>setEmail(e.target.value)} onKeyDown={onKey} style={inp} autoFocus />
            </div>
            <div style={{ marginBottom: 26 }}>
              <label style={lbl}>Passwort</label>
              <input type="password" value={password} onChange={e=>setPassword(e.target.value)} onKeyDown={onKey} style={inp} />
            </div>
            {error && <ErrorBox msg={error} />}
            <SubmitBtn label={loading ? "Anmelden…" : "Anmelden"} loading={loading} onClick={doLogin} />
          </>
        )}
      </div>
    </div>
  );
}

function ErrorBox({ msg }) {
  return (
    <div style={{
      background: T.criticalBg, border: `1px solid ${T.criticalBorder}`,
      borderRadius: 6, padding: "10px 14px", marginBottom: 16,
      fontFamily: T.fontSans, fontSize: 12, color: T.critical,
    }}>{msg}</div>
  );
}

function SubmitBtn({ label, loading, onClick }) {
  return (
    <button onClick={onClick} disabled={loading} style={{
      width: "100%", background: loading ? T.bg4 : T.accent, border: "none",
      borderRadius: 6, padding: "13px", fontFamily: T.fontSans, fontSize: 14,
      fontWeight: 700, color: loading ? T.text3 : "#052e16",
      cursor: loading ? "default" : "pointer", transition: "all 0.15s",
    }}>{label}</button>
  );
}
