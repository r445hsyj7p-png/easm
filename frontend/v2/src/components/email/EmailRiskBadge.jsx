import { T, alpha } from "../../theme";

const BAND_COLORS = {
  Critical: { fg: "var(--critical)", bg: alpha("var(--critical)", 12), border: alpha("var(--critical)", 25) },
  High:     { fg: "var(--high)",     bg: alpha("var(--high)", 12),     border: alpha("var(--high)", 25)     },
  Medium:   { fg: "var(--medium)",   bg: alpha("var(--medium)", 12),   border: alpha("var(--medium)", 25)   },
  Low:      { fg: T.accent,          bg: alpha(T.accent, 10),          border: alpha(T.accent, 22)          },
};

export function EmailRiskBadge({ score, band, size = "md" }) {
  if (score == null) return null;
  const colors = BAND_COLORS[band] ?? BAND_COLORS.Low;
  const compact = size === "sm";

  return (
    <div style={{
      display: "inline-flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center",
      background: colors.bg,
      border: `1px solid ${colors.border}`,
      borderRadius: compact ? 8 : 12,
      padding: compact ? "6px 12px" : "14px 24px",
      minWidth: compact ? 60 : 100,
    }}>
      <span style={{
        fontFamily: T.font,
        fontSize: compact ? 20 : 36,
        fontWeight: 800,
        color: colors.fg,
        lineHeight: 1,
      }}>{score}</span>
      <span style={{
        fontFamily: T.fontSans,
        fontSize: compact ? 9 : 11,
        fontWeight: 700,
        color: colors.fg,
        letterSpacing: "0.06em",
        marginTop: 3,
        textTransform: "uppercase",
      }}>{band}</span>
    </div>
  );
}
