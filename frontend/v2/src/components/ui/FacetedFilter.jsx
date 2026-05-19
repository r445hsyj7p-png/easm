import { useState, useRef, useEffect } from "react";
import { ChevronDown, Check, X } from "lucide-react";
import { T, alpha } from "../../theme";

/* FacetedFilter — multi-select dropdown with facet counts.
   options: [{ value, label, count?, color? }]
   value: string[] (selected values)
   onChange: (string[]) => void */
export function FacetedFilter({ label, options = [], value = [], onChange }) {
  const [open, setOpen] = useState(false);
  const ref             = useRef(null);

  useEffect(() => {
    const handler = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const toggle = opt => {
    const next = value.includes(opt)
      ? value.filter(v => v !== opt)
      : [...value, opt];
    onChange(next);
  };

  const hasActive = value.length > 0;

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: "flex", alignItems: "center", gap: 6,
          padding: "6px 10px", background: hasActive ? alpha(T.accent, 7) : T.bg3,
          border: `1px solid ${hasActive ? alpha(T.accent, 30) : T.border}`,
          borderRadius: 6, fontFamily: T.fontSans, fontSize: 12,
          color: hasActive ? T.accent : T.text2, cursor: "pointer",
          transition: "all 0.12s",
        }}
      >
        {label}
        {hasActive && (
          <>
            <span style={{
              background: T.accent, color: "var(--background)",
              borderRadius: 999, fontFamily: T.font, fontSize: 9,
              fontWeight: 700, padding: "0 5px", lineHeight: "16px",
            }}>{value.length}</span>
            <span
              onClick={e => { e.stopPropagation(); onChange([]); }}
              style={{ display: "flex", alignItems: "center", color: T.text3, cursor: "pointer" }}
            >
              <X size={11} />
            </span>
          </>
        )}
        <ChevronDown size={12} style={{ transform: open ? "rotate(180deg)" : "none", transition: "transform 0.15s" }} />
      </button>

      {open && (
        <div style={{
          position: "absolute", top: "calc(100% + 4px)", left: 0, zIndex: 200,
          background: T.bg2, border: `1px solid ${T.border}`,
          borderRadius: 8, minWidth: 180, maxHeight: 280, overflowY: "auto",
          boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
        }}>
          {options.map(opt => {
            const isSelected = value.includes(opt.value);
            return (
              <button
                key={opt.value}
                onClick={() => toggle(opt.value)}
                style={{
                  display: "flex", alignItems: "center", gap: 8,
                  width: "100%", padding: "8px 12px", background: "transparent",
                  border: "none", cursor: "pointer", textAlign: "left",
                  transition: "background 0.1s",
                }}
                onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                <div style={{
                  width: 14, height: 14, borderRadius: 3, flexShrink: 0,
                  border: `1px solid ${isSelected ? T.accent : T.border}`,
                  background: isSelected ? T.accent : "transparent",
                  display: "flex", alignItems: "center", justifyContent: "center",
                }}>
                  {isSelected && <Check size={9} color="var(--background)" />}
                </div>
                {opt.color && (
                  <div style={{ width: 8, height: 8, borderRadius: "50%", background: opt.color, flexShrink: 0 }} />
                )}
                <span style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text1, flex: 1 }}>{opt.label}</span>
                {opt.count != null && (
                  <span style={{ fontFamily: T.font, fontSize: 10, color: T.text3 }}>{opt.count}</span>
                )}
              </button>
            );
          })}
          {options.length === 0 && (
            <div style={{ padding: "12px 16px", fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>
              Keine Optionen
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* Single-select pill row — simpler than dropdown, shows all options inline */
export function PillFilter({ options, value, onChange }) {
  return (
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
      {options.map(opt => {
        const active = value === opt.value;
        return (
          <button key={opt.value} onClick={() => onChange(active ? "ALL" : opt.value)} style={{
            padding: "4px 10px", borderRadius: 20, fontFamily: T.font, fontSize: 10, fontWeight: 700,
            background: active ? (opt.color ? alpha(opt.color, 13) : alpha(T.accent, 13)) : "transparent",
            border: `1px solid ${active ? (opt.color || T.accent) : T.border}`,
            color: active ? (opt.color || T.accent) : T.text3,
            cursor: "pointer", transition: "all 0.12s",
          }}>
            {opt.label}
            {opt.count != null && active && <span style={{ marginLeft: 4, opacity: 0.7 }}>({opt.count})</span>}
          </button>
        );
      })}
    </div>
  );
}

/* Pagination controls */
export function Pagination({ page, totalPages, onPage }) {
  if (totalPages <= 1) return null;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, justifyContent: "center", padding: "12px 0" }}>
      <PaginBtn onClick={() => onPage(1)} disabled={page <= 1}>«</PaginBtn>
      <PaginBtn onClick={() => onPage(page - 1)} disabled={page <= 1}>‹</PaginBtn>
      <span style={{ fontFamily: T.font, fontSize: 11, color: T.text2, padding: "0 8px" }}>
        {page} / {totalPages}
      </span>
      <PaginBtn onClick={() => onPage(page + 1)} disabled={page >= totalPages}>›</PaginBtn>
      <PaginBtn onClick={() => onPage(totalPages)} disabled={page >= totalPages}>»</PaginBtn>
    </div>
  );
}

function PaginBtn({ children, onClick, disabled }) {
  return (
    <button onClick={onClick} disabled={disabled} style={{
      width: 28, height: 28, display: "flex", alignItems: "center", justifyContent: "center",
      background: "transparent", border: `1px solid ${T.border}`, borderRadius: 4,
      fontFamily: T.font, fontSize: 13, color: disabled ? T.text4 : T.text2,
      cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.4 : 1,
    }}>{children}</button>
  );
}
