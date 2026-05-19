import { T, SEV } from "../../theme";

/* ── Severity badge ──────────────────────────────────────────────────────── */
export function SevBadge({ sev, small }) {
  const s = SEV[sev] || SEV.INFO;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      fontFamily: T.font, fontSize: small ? 9 : 10, fontWeight: 700,
      color: s.color, background: s.bg, border: `1px solid ${s.border}`,
      padding: small ? "0 5px" : "1px 7px", borderRadius: 3, letterSpacing: "0.04em",
      whiteSpace: "nowrap", lineHeight: small ? "16px" : "18px",
    }}>{sev}</span>
  );
}

/* ── Status badge ────────────────────────────────────────────────────────── */
const STATUS_STYLE = {
  open:     { color: T.critical, bg: T.criticalBg, border: T.criticalBorder },
  closed:   { color: T.accent,   bg: T.accent3,    border: `${T.accent}30`  },
  accepted: { color: T.medium,   bg: T.mediumBg,   border: T.mediumBorder   },
};
export function StatusBadge({ status }) {
  const s = STATUS_STYLE[status] || STATUS_STYLE.open;
  return (
    <span style={{
      fontFamily: T.font, fontSize: 9, fontWeight: 700, color: s.color,
      background: s.bg, border: `1px solid ${s.border}`,
      padding: "1px 7px", borderRadius: 3, letterSpacing: "0.04em",
      whiteSpace: "nowrap",
    }}>{status?.toUpperCase() || "OPEN"}</span>
  );
}

/* ── KPI card ────────────────────────────────────────────────────────────── */
export function KpiCard({ label, value, sub, color, onClick, icon: Icon }) {
  return (
    <div
      onClick={onClick}
      style={{
        background: T.bg2, border: `1px solid ${T.border}`,
        borderRadius: 8, padding: "16px 20px",
        cursor: onClick ? "pointer" : "default",
        transition: "border-color 0.15s, transform 0.1s",
        userSelect: "none",
      }}
      onMouseEnter={e => { if (onClick) { e.currentTarget.style.borderColor = color || T.accent; e.currentTarget.style.transform = "translateY(-1px)"; }}}
      onMouseLeave={e => { if (onClick) { e.currentTarget.style.borderColor = T.border; e.currentTarget.style.transform = "none"; }}}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3, textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</div>
        {Icon && <Icon size={15} color={color || T.text3} />}
      </div>
      <div style={{ fontFamily: T.font, fontSize: 28, fontWeight: 700, color: color || T.text0, lineHeight: 1, marginBottom: 4 }}>{value}</div>
      {sub && <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3 }}>{sub}</div>}
    </div>
  );
}

/* ── Spinner ─────────────────────────────────────────────────────────────── */
export function Spinner({ size = 20 }) {
  return (
    <div style={{
      width: size, height: size,
      border: `2px solid ${T.border}`,
      borderTopColor: T.accent,
      borderRadius: "50%",
      animation: "spin 0.7s linear infinite",
      flexShrink: 0,
    }} />
  );
}

/* ── Page loading screen ─────────────────────────────────────────────────── */
export function PageLoading() {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 80, gap: 12 }}>
      <Spinner />
      <span style={{ fontFamily: T.font, fontSize: 11, color: T.text3, letterSpacing: "0.06em" }}>Laden…</span>
    </div>
  );
}

/* ── Empty state ─────────────────────────────────────────────────────────── */
export function EmptyState({ icon: Icon, title, sub }) {
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
      padding: "60px 24px", gap: 12, textAlign: "center",
    }}>
      {Icon && <Icon size={36} color={T.text4} strokeWidth={1.5} />}
      <div style={{ fontFamily: T.fontSans, fontSize: 14, fontWeight: 600, color: T.text2 }}>{title}</div>
      {sub && <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3, maxWidth: 360, lineHeight: 1.6 }}>{sub}</div>}
    </div>
  );
}

/* ── Section card ────────────────────────────────────────────────────────── */
export function Card({ children, style }) {
  return (
    <div style={{ background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 8, overflow: "hidden", ...style }}>
      {children}
    </div>
  );
}

/* ── Card header ─────────────────────────────────────────────────────────── */
export function CardHeader({ title, sub, actions }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "14px 18px", borderBottom: `1px solid ${T.border}`,
      background: T.bg3,
    }}>
      <div>
        <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0 }}>{title}</div>
        {sub && <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3, marginTop: 2 }}>{sub}</div>}
      </div>
      {actions && <div style={{ display: "flex", gap: 8, alignItems: "center" }}>{actions}</div>}
    </div>
  );
}

/* ── Table primitives ────────────────────────────────────────────────────── */
export function TH({ children, onClick, sorted, style }) {
  return (
    <th onClick={onClick} style={{
      fontFamily: T.font, fontSize: 9, fontWeight: 700, color: sorted ? T.accent : T.text3,
      padding: "8px 12px", textAlign: "left", background: T.bg3,
      borderBottom: `1px solid ${T.border}`, letterSpacing: "0.08em",
      textTransform: "uppercase", whiteSpace: "nowrap",
      cursor: onClick ? "pointer" : "default",
      userSelect: "none", ...style,
    }}>
      {children}{onClick && (sorted ? " ↑" : " ↕")}
    </th>
  );
}

export function TD({ children, style }) {
  return (
    <td style={{
      fontFamily: T.fontSans, fontSize: 12, color: T.text1,
      padding: "9px 12px", borderBottom: `1px solid ${T.border}`,
      verticalAlign: "middle", ...style,
    }}>
      {children}
    </td>
  );
}

/* ── Filter pill button ──────────────────────────────────────────────────── */
export function FilterPill({ label, active, color, onClick }) {
  return (
    <button onClick={onClick} style={{
      padding: "4px 10px", borderRadius: 20, fontFamily: T.font, fontSize: 10, fontWeight: 700,
      background: active ? (color ? `${color}20` : T.bg4) : "transparent",
      border: `1px solid ${active ? (color || T.accent) : T.border}`,
      color: active ? (color || T.accent) : T.text3,
      cursor: "pointer", transition: "all 0.12s", whiteSpace: "nowrap",
    }}>
      {label}
    </button>
  );
}

/* ── Text input ──────────────────────────────────────────────────────────── */
export function SearchInput({ value, onChange, placeholder, width = 220 }) {
  return (
    <input
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder || "Suchen…"}
      style={{
        background: T.bg3, border: `1px solid ${T.border}`, borderRadius: 6,
        padding: "7px 12px", fontFamily: T.fontSans, fontSize: 12, color: T.text0,
        outline: "none", width,
      }}
    />
  );
}

/* ── Primary button ──────────────────────────────────────────────────────── */
export function Btn({ children, onClick, variant = "default", disabled, style }) {
  const styles = {
    primary: { background: T.accent, color: "#052e16", border: "none" },
    danger:  { background: T.criticalBg, color: T.critical, border: `1px solid ${T.criticalBorder}` },
    default: { background: T.bg3, color: T.text1, border: `1px solid ${T.border}` },
  };
  return (
    <button onClick={onClick} disabled={disabled} style={{
      display: "inline-flex", alignItems: "center", gap: 6,
      padding: "7px 14px", borderRadius: 6, fontFamily: T.font, fontSize: 11, fontWeight: 700,
      cursor: disabled ? "default" : "pointer", letterSpacing: "0.04em",
      opacity: disabled ? 0.5 : 1, transition: "opacity 0.15s",
      ...styles[variant], ...style,
    }}>
      {children}
    </button>
  );
}
