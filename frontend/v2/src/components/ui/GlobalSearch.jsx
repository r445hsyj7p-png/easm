import { useState, useEffect, useRef, useCallback } from "react";
import { Search, X, AlertTriangle, Globe, FileText } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { T, SEV, alpha } from "../../theme";
import { apiFetch } from "../../api/client";

export function GlobalSearch() {
  const navigate       = useNavigate();
  const inputRef       = useRef(null);
  const containerRef   = useRef(null);
  const debounceRef    = useRef(null);

  const [query,       setQuery]      = useState("");
  const [results,     setResults]    = useState(null);
  const [loading,     setLoading]    = useState(false);
  const [open,        setOpen]       = useState(false);
  const [syntax,      setSyntax]     = useState(null);
  const [showSyntax,  setShowSyntax] = useState(false);

  // Load syntax once for hints
  useEffect(() => {
    apiFetch("/search/syntax").then(setSyntax).catch(() => {});
  }, []);

  // ⌘K / Ctrl+K to focus, Escape to close
  useEffect(() => {
    const handler = e => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        inputRef.current?.focus();
        setOpen(true);
      }
      if (e.key === "Escape") { setOpen(false); inputRef.current?.blur(); }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  // Click outside to close
  useEffect(() => {
    const handler = e => {
      if (containerRef.current && !containerRef.current.contains(e.target)) {
        setOpen(false);
        setShowSyntax(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const doSearch = useCallback(async q => {
    if (!q || q.trim().length < 2) { setResults(null); return; }
    setLoading(true);
    try {
      const data = await apiFetch(`/search?q=${encodeURIComponent(q.trim())}&scope=all&limit=20`);
      setResults(data);
    } catch {
      setResults(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const handleChange = e => {
    const q = e.target.value;
    setQuery(q);
    setOpen(true);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => doSearch(q), 300);
  };

  const handleSelect = result => {
    setOpen(false); setQuery(""); setResults(null);
    if      (result._type === "finding") navigate("/findings");
    else if (result._type === "asset")   navigate("/assetsnew");
    else if (result._type === "domain")  navigate("/targets");
  };

  const useExample = ex => {
    setQuery(ex); setShowSyntax(false); setOpen(true); doSearch(ex);
  };

  const findings = (results?.findings || []).map(r => ({ ...r, _type: "finding" }));
  const assets   = (results?.assets   || []).map(r => ({ ...r, _type: "asset"   }));
  const domains  = (results?.domains  || []).map(r => ({ ...r, _type: "domain"  }));
  const total    = findings.length + assets.length + domains.length;

  return (
    <div ref={containerRef} style={{ position: "relative", flex: 1, maxWidth: 380 }}>
      {/* Input */}
      <div style={{
        display: "flex", alignItems: "center", gap: 8,
        background: T.bg3, border: `1px solid ${open ? T.borderFocus : T.border}`,
        borderRadius: 6, padding: "5px 10px", transition: "border-color 0.15s",
      }}>
        <Search size={12} color={T.text3} style={{ flexShrink: 0 }} />
        <input
          ref={inputRef}
          value={query}
          onChange={handleChange}
          onFocus={() => setOpen(true)}
          placeholder="Suchen… (⌘K)"
          style={{
            flex: 1, background: "none", border: "none", outline: "none",
            fontFamily: T.font, fontSize: 12, color: T.text0, minWidth: 0,
          }}
        />
        {query ? (
          <button onClick={() => { setQuery(""); setResults(null); inputRef.current?.focus(); }} style={{
            background: "none", border: "none", color: T.text3, cursor: "pointer",
            display: "flex", alignItems: "center", flexShrink: 0,
          }}><X size={11} /></button>
        ) : (
          <button
            onClick={() => setShowSyntax(s => !s)}
            style={{
              background: showSyntax ? alpha(T.accent, 10) : "none",
              border: `1px solid ${showSyntax ? alpha(T.accent, 25) : T.border}`,
              borderRadius: 3, fontFamily: T.font, fontSize: 9,
              color: showSyntax ? T.accent : T.text4, cursor: "pointer",
              padding: "1px 5px", lineHeight: "14px", flexShrink: 0,
            }}
            title="Suchsyntax"
          >?</button>
        )}
      </div>

      {/* Syntax panel */}
      {showSyntax && syntax && (
        <div style={{
          position: "absolute", top: "calc(100% + 6px)", left: 0, zIndex: 400,
          background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 8,
          padding: "14px 16px", width: 380, boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
        }}>
          <div style={{ fontFamily: T.font, fontSize: 9, color: T.text4, letterSpacing: "0.08em", marginBottom: 10 }}>
            FILTER-SYNTAX
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4, marginBottom: 12 }}>
            {Object.entries(syntax.filters || {}).map(([, v]) => (
              <div key={v.syntax} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <code style={{
                  fontFamily: T.font, fontSize: 10, color: T.accent,
                  background: T.accent3, border: `1px solid ${alpha(T.accent, 19)}`,
                  padding: "1px 6px", borderRadius: 3,
                }}>{v.syntax}</code>
              </div>
            ))}
          </div>
          <div style={{ fontFamily: T.font, fontSize: 9, color: T.text4, letterSpacing: "0.08em", marginBottom: 6 }}>
            BEISPIELE — klicken zum Ausführen
          </div>
          {(syntax.examples || []).map((ex, i) => (
            <div key={i} onClick={() => useExample(ex)} style={{
              fontFamily: T.font, fontSize: 10, color: T.text2,
              padding: "4px 6px", borderRadius: 3, cursor: "pointer", marginBottom: 2,
            }}
              onMouseEnter={e => e.currentTarget.style.background = T.bg3}
              onMouseLeave={e => e.currentTarget.style.background = "transparent"}
            >{ex}</div>
          ))}
        </div>
      )}

      {/* Results dropdown */}
      {open && !showSyntax && query.trim().length >= 2 && (
        <div style={{
          position: "absolute", top: "calc(100% + 6px)", left: 0, right: 0, zIndex: 400,
          background: T.bg2, border: `1px solid ${T.border}`, borderRadius: 8,
          maxHeight: 380, overflowY: "auto", boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
        }}>
          {loading && (
            <div style={{ padding: "14px 16px", fontFamily: T.font, fontSize: 11, color: T.text3 }}>
              Suche läuft…
            </div>
          )}
          {!loading && results && total === 0 && (
            <div style={{ padding: "14px 16px", fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>
              Keine Ergebnisse für <em>„{query}"</em>
            </div>
          )}
          {!loading && total > 0 && (
            <>
              {[
                { key: "finding", items: findings, label: "FINDINGS",  Icon: AlertTriangle },
                { key: "asset",   items: assets,   label: "ASSETS",    Icon: Globe        },
                { key: "domain",  items: domains,  label: "DOMAINS",   Icon: FileText     },
              ].map(({ key, items, label, Icon }) => items.length === 0 ? null : (
                <div key={key}>
                  <div style={{
                    padding: "8px 14px 4px",
                    fontFamily: T.font, fontSize: 9, color: T.text4, letterSpacing: "0.08em",
                    display: "flex", alignItems: "center", gap: 6,
                  }}>
                    <Icon size={9} />
                    {label} ({items.length})
                  </div>
                  {items.map((r, i) => (
                    <button key={i} onClick={() => handleSelect(r)} style={{
                      display: "flex", alignItems: "center", gap: 8,
                      width: "100%", padding: "8px 14px", background: "transparent",
                      border: "none", cursor: "pointer", textAlign: "left",
                    }}
                      onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      {key === "finding" && r.sev && (
                        <span style={{
                          fontFamily: T.font, fontSize: 8, fontWeight: 700,
                          color: SEV[r.sev]?.color || T.text3,
                          background: SEV[r.sev]?.bg || T.bg4,
                          border: `1px solid ${SEV[r.sev]?.border || T.border}`,
                          padding: "0 4px", borderRadius: 2, flexShrink: 0,
                        }}>{r.sev}</span>
                      )}
                      <span style={{
                        fontFamily: T.fontSans, fontSize: 12, color: T.text0, flex: 1,
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                      }}>
                        {r.title || r.fqdn || r.domain || r.ip || "—"}
                      </span>
                      {(r.asset || r.ip) && (
                        <span style={{ fontFamily: T.font, fontSize: 10, color: T.text3, flexShrink: 0 }}>
                          {r.asset || r.ip}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              ))}
              <div style={{
                padding: "8px 14px", borderTop: `1px solid ${T.border}`,
                fontFamily: T.font, fontSize: 10, color: T.text4,
              }}>
                {total} Ergebnis{total !== 1 ? "se" : ""}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
