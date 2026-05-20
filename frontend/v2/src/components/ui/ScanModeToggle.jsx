import { Eye, Zap, Info } from "lucide-react";
import { useState } from "react";
import { T, alpha } from "../../theme";

const MODES = [
  {
    value: "passive",
    label: "Passiv",
    Icon: Eye,
    description: "Nur OSINT — kein Kontakt mit Zielsystemen",
    detail: "Subfinder · theHarvester · HIBP · GreyNoise · AbuseIPDB · OTX\nKein Port-Scan, kein HTTP-Probing, keine Exploit-Templates.",
  },
  {
    value: "active",
    label: "Aktiv",
    Icon: Zap,
    description: "Vollständig inkl. Port-Scan & Vuln-Templates",
    detail: "Zusätzlich: Naabu (Port-Scan) · HTTPX · SSLyze · Nuclei · Ramparts\nHinterlässt Spuren in Access-Logs des Ziels.",
  },
];

export function ScanModeToggle({ mode, onChange, size = "md" }) {
  const [tooltip, setTooltip] = useState(null);
  const compact = size === "sm";

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      {/* Segmented control */}
      <div style={{
        display: "flex",
        background: T.bg3,
        border: `1px solid ${T.border}`,
        borderRadius: 7,
        padding: 2,
        gap: 2,
      }}>
        {MODES.map(({ value, label, Icon }) => {
          const active = mode === value;
          return (
            <button
              key={value}
              onClick={() => onChange(value)}
              style={{
                display: "flex", alignItems: "center",
                gap: compact ? 4 : 6,
                padding: compact ? "4px 10px" : "6px 14px",
                background: active ? (value === "active" ? T.accent : T.bg2) : "transparent",
                border: active
                  ? `1px solid ${value === "active" ? T.accent : T.border}`
                  : "1px solid transparent",
                borderRadius: 5,
                fontFamily: T.fontSans,
                fontSize: compact ? 11 : 12,
                fontWeight: active ? 600 : 400,
                color: active
                  ? (value === "active" ? "var(--background)" : T.text1)
                  : T.text3,
                cursor: "pointer",
                transition: "all 0.12s",
              }}
              onMouseEnter={e => {
                if (!active) {
                  e.currentTarget.style.background = T.bg4;
                  e.currentTarget.style.color = T.text2;
                }
              }}
              onMouseLeave={e => {
                if (!active) {
                  e.currentTarget.style.background = "transparent";
                  e.currentTarget.style.color = T.text3;
                }
              }}
            >
              <Icon size={compact ? 11 : 13} />
              {label}
            </button>
          );
        })}
      </div>

      {/* Info button with tooltip */}
      <div style={{ position: "relative" }}>
        <button
          onMouseEnter={() => setTooltip(mode)}
          onMouseLeave={() => setTooltip(null)}
          style={{
            background: "none", border: "none", cursor: "pointer",
            color: T.text4, display: "flex", alignItems: "center", padding: 2,
          }}
        >
          <Info size={13} />
        </button>

        {tooltip && (() => {
          const m = MODES.find(m => m.value === tooltip);
          return (
            <div style={{
              position: "absolute", left: "100%", top: "50%",
              transform: "translateY(-50%)", marginLeft: 8,
              zIndex: 500, width: 280,
              background: T.bg2, border: `1px solid ${T.border}`,
              borderRadius: 8, padding: "12px 14px",
              boxShadow: "0 8px 24px rgba(0,0,0,0.35)",
              pointerEvents: "none",
            }}>
              <div style={{
                fontFamily: T.fontSans, fontSize: 12, fontWeight: 600,
                color: T.text0, marginBottom: 4,
              }}>{m.label}</div>
              <div style={{
                fontFamily: T.fontSans, fontSize: 11, color: T.text3,
                marginBottom: 8,
              }}>{m.description}</div>
              <div style={{
                fontFamily: T.font, fontSize: 10, color: T.text4,
                lineHeight: 1.6, whiteSpace: "pre-line",
              }}>{m.detail}</div>
            </div>
          );
        })()}
      </div>

      {/* Inline description — only in full size */}
      {!compact && (
        <span style={{
          fontFamily: T.fontSans, fontSize: 11, color: T.text4,
        }}>
          {MODES.find(m => m.value === mode)?.description}
        </span>
      )}
    </div>
  );
}

/** Badge shown in scan history rows */
export function ScanModeBadge({ mode }) {
  const isPassive = mode === "passive";
  return (
    <span style={{
      fontFamily: T.font, fontSize: 9, fontWeight: 700,
      color: isPassive ? T.text3 : T.accent,
      background: isPassive ? T.bg4 : alpha(T.accent, 10),
      border: `1px solid ${isPassive ? T.border : alpha(T.accent, 25)}`,
      padding: "1px 6px", borderRadius: 3,
    }}>
      {isPassive ? "PASSIV" : "AKTIV"}
    </span>
  );
}

/** Parse the stored scan_type string: "full/active", "quick", "full" → { type, mode } */
export function parseScanType(raw = "") {
  const [type, mode] = raw.split("/");
  return {
    type: type || "full",
    mode: mode || (type === "quick" ? "passive" : "active"),
  };
}
