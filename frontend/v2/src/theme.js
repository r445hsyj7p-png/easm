export const T = {
  bg0: "#050810", bg1: "#080c18", bg2: "#0d1221",
  bg3: "#121929", bg4: "#172131", bg5: "#1d2a3d",
  border: "#1e2d45", border2: "#253554", borderFocus: "#22c55e",
  accent: "#22c55e", accent2: "#16a34a", accent3: "#0f3d20",
  critical: "#f43f5e", criticalBg: "#1c0810", criticalBorder: "#7f1d1d",
  high: "#f97316",    highBg: "#1c0e00",     highBorder: "#7c2d12",
  medium: "#eab308",  mediumBg: "#1a1400",   mediumBorder: "#713f12",
  low: "#60a5fa",     lowBg: "#00111e",      lowBorder: "#1e3a5f",
  info: "#94a3b8",    infoBg: "#0d1221",     infoBorder: "#1e2d45",
  text0: "#f1f5f9", text1: "#cbd5e1", text2: "#94a3b8", text3: "#475569", text4: "#273548",
  font:     "'JetBrains Mono', 'Fira Code', monospace",
  fontSans: "'Inter', 'IBM Plex Sans', system-ui, sans-serif",
  red: "#f43f5e", green: "#22c55e",
};

export const SEV = {
  CRITICAL: { color: T.critical, bg: T.criticalBg, border: T.criticalBorder },
  HIGH:     { color: T.high,     bg: T.highBg,     border: T.highBorder     },
  MEDIUM:   { color: T.medium,   bg: T.mediumBg,   border: T.mediumBorder   },
  LOW:      { color: T.low,      bg: T.lowBg,      border: T.lowBorder      },
  INFO:     { color: T.info,     bg: T.infoBg,     border: T.infoBorder     },
};

export const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
