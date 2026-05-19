/* CSS custom property references — resolved at paint time by the browser.
   Components use inline styles; values work with both dark and light theme. */

export const T = {
  /* backgrounds */
  bg0: "var(--background)",
  bg1: "var(--bg-1)",
  bg2: "var(--card)",
  bg3: "var(--secondary)",
  bg4: "var(--muted)",
  bg5: "var(--popover)",

  /* borders */
  border:      "var(--border)",
  border2:     "var(--border-strong)",
  borderFocus: "var(--border-focus)",

  /* accent (green) */
  accent:  "var(--accent)",
  accent2: "var(--accent-dim)",
  accent3: "var(--accent-bg)",

  /* severity foreground */
  critical: "var(--sev-critical)",
  high:     "var(--sev-high)",
  medium:   "var(--sev-medium)",
  low:      "var(--sev-low)",
  info:     "var(--sev-info)",

  /* severity background + border */
  criticalBg:     "var(--sev-critical-bg)",
  criticalBorder: "var(--sev-critical-border)",
  highBg:         "var(--sev-high-bg)",
  highBorder:     "var(--sev-high-border)",
  mediumBg:       "var(--sev-medium-bg)",
  mediumBorder:   "var(--sev-medium-border)",
  lowBg:          "var(--sev-low-bg)",
  lowBorder:      "var(--sev-low-border)",
  infoBg:         "var(--sev-info-bg)",
  infoBorder:     "var(--sev-info-border)",

  /* text scale */
  text0: "var(--foreground)",
  text1: "var(--text-primary)",
  text2: "var(--muted-foreground)",
  text3: "var(--text-muted)",
  text4: "var(--text-faint)",

  /* typography */
  font:     "var(--font-mono)",
  fontSans: "var(--font-sans)",

  /* aliases */
  red:   "var(--sev-critical)",
  green: "var(--accent)",
};

/* alpha() — inline-style-safe alpha compositing via color-mix.
   Supported: Chrome 111+, Firefox 113+, Safari 16.2+.
   Works with any colorVar, including other CSS custom properties. */
export const alpha = (colorVar, percent) =>
  `color-mix(in oklch, ${colorVar} ${percent}%, transparent)`;

export const SEV = {
  CRITICAL: { color: T.critical, bg: T.criticalBg, border: T.criticalBorder },
  HIGH:     { color: T.high,     bg: T.highBg,     border: T.highBorder     },
  MEDIUM:   { color: T.medium,   bg: T.mediumBg,   border: T.mediumBorder   },
  LOW:      { color: T.low,      bg: T.lowBg,      border: T.lowBorder      },
  INFO:     { color: T.info,     bg: T.infoBg,     border: T.infoBorder     },
};

export const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
