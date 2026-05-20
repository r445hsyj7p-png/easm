import { useState, useEffect, useCallback } from "react";
import { toast } from "sonner";
import { Settings, Globe, Shield, Calendar, RefreshCw, Key, Trash2, PauseCircle, PlayCircle, Plus, ChevronDown, ChevronUp } from "lucide-react";
import { T, alpha } from "../theme";
import { Card, CardHeader, KpiCard, PageLoading, Btn } from "../components/ui/index";
import { useApp } from "../context/AppContext";
import { apiFetch } from "../api/client";

export default function SettingsPage() {
  const { tenant, loading, reload, tenantId } = useApp();
  const [saving,        setSaving]       = useState(false);
  const [schedule,      setSchedule]     = useState("");
  const [editSchedule,  setEditSchedule] = useState(false);

  // Domain management state
  const [domains,      setDomains]      = useState([]);
  const [domainsLoading, setDomainsLoading] = useState(true);
  const [showAddDomain,  setShowAddDomain]  = useState(false);
  const [newDomain,    setNewDomain]    = useState("");
  const [newIpRanges,  setNewIpRanges]  = useState("");
  const [newPanos,     setNewPanos]     = useState("");
  const [expandedId,   setExpandedId]   = useState(null);
  const [editIpRanges, setEditIpRanges] = useState({});
  const [editPanos,    setEditPanos]    = useState({});
  const [confirmDelete, setConfirmDelete] = useState(null);

  const fetchDomains = useCallback(async () => {
    setDomainsLoading(true);
    try {
      const data = await apiFetch(`/tenants/${tenantId}/domains`);
      setDomains(data.domains ?? data);
    } catch { /* silent */ }
    finally { setDomainsLoading(false); }
  }, [tenantId]);

  useEffect(() => { fetchDomains(); }, [fetchDomains]);

  if (loading) return <PageLoading />;

  const lastScanStr = tenant.last_scan
    ? new Date(tenant.last_scan).toLocaleString("de-DE", { dateStyle: "medium", timeStyle: "short" })
    : "Noch kein Scan";
  const nextScanStr = tenant.next_scan
    ? new Date(tenant.next_scan).toLocaleString("de-DE", { dateStyle: "medium", timeStyle: "short" })
    : "—";

  // ── Domain handlers ────────────────────────────────────────────────────────

  const handleAddDomain = async () => {
    if (!newDomain.trim()) return;
    setSaving(true);
    try {
      const ranges = newIpRanges.split(",").map(s => s.trim()).filter(Boolean);
      await apiFetch(`/tenants/${tenantId}/domains`, {
        method: "POST",
        body: { domain: newDomain.trim(), ip_ranges: ranges, panos_version: newPanos.trim() },
      });
      toast.success("Domain hinzugefügt");
      setNewDomain(""); setNewIpRanges(""); setNewPanos(""); setShowAddDomain(false);
      fetchDomains(); reload();
    } catch (e) { toast.error("Fehler", { description: e.message }); }
    finally { setSaving(false); }
  };

  const handleToggleStatus = async (d) => {
    const next = d.status === "active" ? "paused" : "active";
    try {
      await apiFetch(`/tenants/${tenantId}/domains/${d.id}`, {
        method: "PATCH", body: { status: next },
      });
      setDomains(prev => prev.map(x => x.id === d.id ? { ...x, status: next } : x));
      toast.success(`Domain ${next === "active" ? "aktiviert" : "pausiert"}`);
    } catch (e) { toast.error("Fehler", { description: e.message }); }
  };

  const handleUpdateDomain = async (d) => {
    const ranges = (editIpRanges[d.id] ?? (d.ip_ranges || []).join(", "))
      .split(",").map(s => s.trim()).filter(Boolean);
    const panos  = editPanos[d.id] ?? d.panos_version ?? "";
    try {
      await apiFetch(`/tenants/${tenantId}/domains/${d.id}`, {
        method: "PATCH", body: { ip_ranges: ranges, panos_version: panos },
      });
      toast.success("Domain aktualisiert");
      setExpandedId(null);
      fetchDomains();
    } catch (e) { toast.error("Fehler", { description: e.message }); }
  };

  const handleDelete = async (id) => {
    try {
      await apiFetch(`/tenants/${tenantId}/domains/${id}`, { method: "DELETE" });
      setDomains(prev => prev.filter(d => d.id !== id));
      setConfirmDelete(null);
      if (expandedId === id) setExpandedId(null);
      toast.success("Domain gelöscht");
      reload();
    } catch (e) { toast.error("Fehler", { description: e.message }); }
  };

  // ── Schedule handler ───────────────────────────────────────────────────────

  const handleSaveSchedule = async () => {
    setSaving(true);
    try {
      const current = await apiFetch(`/tenants/${tenantId}/settings`);
      await apiFetch(`/tenants/${tenantId}/settings`, {
        method: "PUT", body: { ...current, scan_schedule: schedule },
      });
      toast.success("Scan-Intervall gespeichert");
      setEditSchedule(false);
      reload();
    } catch (e) { toast.error("Fehler", { description: e.message }); }
    finally { setSaving(false); }
  };

  const scoreColor = (tenant.score || 0) >= 70 ? T.accent : (tenant.score || 0) >= 40 ? T.medium : T.critical;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20, maxWidth: 900 }}>
      <div>
        <div style={{ fontFamily: T.fontSans, fontSize: 18, fontWeight: 700, color: T.text0, marginBottom: 4 }}>
          Einstellungen
        </div>
        <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>
          Tenant-Konfiguration und Plattform-Einstellungen
        </div>
      </div>

      {/* KPI row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
        <KpiCard label="Risk Score"    value={tenant.score ?? "—"} color={scoreColor} sub={`Grade ${tenant.grade || "?"}`} icon={Shield} />
        <KpiCard label="Letzter Scan"  value={lastScanStr} icon={Calendar} />
        <KpiCard label="Nächster Scan" value={nextScanStr} color={T.accent} icon={RefreshCw} />
      </div>

      {/* ── Domain management ── */}
      <Card>
        <CardHeader title="Domains" icon={<Globe size={15} color={T.text3} />} />
        <div style={{ padding: "16px 20px", display: "flex", flexDirection: "column", gap: 0 }}>

          {/* Domain list */}
          {domainsLoading ? (
            <div style={{ fontFamily: T.font, fontSize: 11, color: T.text3, padding: "8px 0" }}>Lädt…</div>
          ) : domains.length === 0 ? (
            <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3, padding: "8px 0" }}>
              Keine Domains konfiguriert.
            </div>
          ) : (
            domains.map((d, i) => {
              const isExpanded = expandedId === d.id;
              const isActive   = d.status === "active";
              return (
                <div key={d.id} style={{
                  borderBottom: i < domains.length - 1 ? `1px solid ${T.border}` : "none",
                  paddingBottom: 12, marginBottom: 12,
                }}>
                  {/* Domain row */}
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    {/* Status dot */}
                    <div style={{
                      width: 7, height: 7, borderRadius: "50%", flexShrink: 0,
                      background: isActive ? T.accent : T.text4,
                    }} />

                    {/* Domain name */}
                    <span style={{ fontFamily: T.font, fontSize: 13, color: isActive ? T.text0 : T.text3, flex: 1 }}>
                      {d.domain || d.fqdn}
                    </span>

                    {/* Status badge */}
                    <span style={{
                      fontFamily: T.font, fontSize: 9, fontWeight: 700,
                      color: isActive ? T.accent : T.text3,
                      background: isActive ? T.accent3 : T.bg4,
                      border: `1px solid ${isActive ? alpha(T.accent, 25) : T.border}`,
                      padding: "1px 6px", borderRadius: 3,
                    }}>{isActive ? "AKTIV" : "PAUSIERT"}</span>

                    {/* Toggle status */}
                    <button
                      onClick={() => handleToggleStatus(d)}
                      title={isActive ? "Pausieren" : "Aktivieren"}
                      style={{
                        background: "none", border: `1px solid ${T.border}`, borderRadius: 4,
                        padding: "3px 6px", cursor: "pointer", color: T.text3,
                        display: "flex", alignItems: "center",
                      }}
                    >
                      {isActive ? <PauseCircle size={13} /> : <PlayCircle size={13} />}
                    </button>

                    {/* Expand for IP ranges / PAN-OS */}
                    <button
                      onClick={() => setExpandedId(isExpanded ? null : d.id)}
                      style={{
                        background: "none", border: `1px solid ${T.border}`, borderRadius: 4,
                        padding: "3px 6px", cursor: "pointer", color: T.text3,
                        display: "flex", alignItems: "center",
                      }}
                      title="Konfiguration bearbeiten"
                    >
                      {isExpanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                    </button>

                    {/* Delete */}
                    {confirmDelete === d.id ? (
                      <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
                        <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.critical }}>Sicher?</span>
                        <Btn onClick={() => handleDelete(d.id)} variant="danger" style={{ padding: "3px 8px", fontSize: 10 }}>Ja</Btn>
                        <Btn onClick={() => setConfirmDelete(null)} variant="ghost" style={{ padding: "3px 8px", fontSize: 10 }}>Nein</Btn>
                      </div>
                    ) : (
                      <button
                        onClick={() => setConfirmDelete(d.id)}
                        style={{
                          background: "none", border: `1px solid ${T.border}`, borderRadius: 4,
                          padding: "3px 6px", cursor: "pointer", color: T.critical,
                          display: "flex", alignItems: "center",
                        }}
                        title="Domain löschen"
                      >
                        <Trash2 size={13} />
                      </button>
                    )}
                  </div>

                  {/* Expanded config */}
                  {isExpanded && (
                    <div style={{
                      marginTop: 10, padding: "12px 14px",
                      background: T.bg3, borderRadius: 6, border: `1px solid ${T.border}`,
                      display: "flex", flexDirection: "column", gap: 10,
                    }}>
                      <div>
                        <label style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3, display: "block", marginBottom: 4 }}>
                          IP-Ranges (kommagetrennt)
                        </label>
                        <input
                          value={editIpRanges[d.id] ?? (d.ip_ranges || []).join(", ")}
                          onChange={e => setEditIpRanges(prev => ({ ...prev, [d.id]: e.target.value }))}
                          placeholder="z.B. 10.0.0.0/8, 192.168.0.0/24"
                          style={{
                            width: "100%", boxSizing: "border-box",
                            padding: "7px 10px", background: T.bg2, border: `1px solid ${T.border}`,
                            borderRadius: 5, fontFamily: T.font, fontSize: 11, color: T.text0, outline: "none",
                          }}
                        />
                      </div>
                      <div>
                        <label style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3, display: "block", marginBottom: 4 }}>
                          PAN-OS Version
                        </label>
                        <input
                          value={editPanos[d.id] ?? (d.panos_version || "")}
                          onChange={e => setEditPanos(prev => ({ ...prev, [d.id]: e.target.value }))}
                          placeholder="z.B. 10.2.4"
                          style={{
                            width: "100%", boxSizing: "border-box",
                            padding: "7px 10px", background: T.bg2, border: `1px solid ${T.border}`,
                            borderRadius: 5, fontFamily: T.font, fontSize: 11, color: T.text0, outline: "none",
                          }}
                        />
                      </div>
                      <div style={{ display: "flex", gap: 8 }}>
                        <Btn onClick={() => handleUpdateDomain(d)} variant="primary">Speichern</Btn>
                        <Btn onClick={() => setExpandedId(null)} variant="ghost">Abbrechen</Btn>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}

          {/* Add domain form */}
          {showAddDomain ? (
            <div style={{
              marginTop: 4, padding: "14px 16px",
              background: T.bg3, borderRadius: 6, border: `1px solid ${T.border}`,
              display: "flex", flexDirection: "column", gap: 10,
            }}>
              <div style={{ fontFamily: T.fontSans, fontSize: 12, fontWeight: 600, color: T.text0 }}>
                Neue Domain
              </div>
              <input
                autoFocus
                value={newDomain}
                onChange={e => setNewDomain(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleAddDomain()}
                placeholder="beispiel.de"
                style={{
                  padding: "8px 10px", background: T.bg2, border: `1px solid ${T.border}`,
                  borderRadius: 5, fontFamily: T.font, fontSize: 12, color: T.text0, outline: "none",
                }}
              />
              <input
                value={newIpRanges}
                onChange={e => setNewIpRanges(e.target.value)}
                placeholder="IP-Ranges (kommagetrennt, optional)"
                style={{
                  padding: "8px 10px", background: T.bg2, border: `1px solid ${T.border}`,
                  borderRadius: 5, fontFamily: T.font, fontSize: 11, color: T.text0, outline: "none",
                }}
              />
              <input
                value={newPanos}
                onChange={e => setNewPanos(e.target.value)}
                placeholder="PAN-OS Version (optional)"
                style={{
                  padding: "8px 10px", background: T.bg2, border: `1px solid ${T.border}`,
                  borderRadius: 5, fontFamily: T.font, fontSize: 11, color: T.text0, outline: "none",
                }}
              />
              <div style={{ display: "flex", gap: 8 }}>
                <Btn onClick={handleAddDomain} variant="primary" disabled={saving || !newDomain.trim()}>
                  {saving ? "…" : "Hinzufügen"}
                </Btn>
                <Btn onClick={() => { setShowAddDomain(false); setNewDomain(""); setNewIpRanges(""); setNewPanos(""); }} variant="ghost">
                  Abbrechen
                </Btn>
              </div>
            </div>
          ) : (
            <button
              onClick={() => setShowAddDomain(true)}
              style={{
                display: "flex", alignItems: "center", gap: 6,
                background: "none", border: `1px dashed ${T.border}`, borderRadius: 6,
                padding: "8px 14px", fontFamily: T.fontSans, fontSize: 12,
                color: T.text3, cursor: "pointer", width: "100%",
                marginTop: domains.length > 0 ? 4 : 0, transition: "border-color 0.15s, color 0.15s",
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = T.accent; e.currentTarget.style.color = T.accent; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = T.border;  e.currentTarget.style.color = T.text3;  }}
            >
              <Plus size={13} />Domain hinzufügen
            </button>
          )}
        </div>
      </Card>

      {/* Scan schedule */}
      <Card>
        <CardHeader title="Scan-Konfiguration" icon={<RefreshCw size={15} color={T.text3} />} />
        <div style={{ padding: "20px 24px" }}>
          <SettingRow
            label="Scan-Intervall"
            value={tenant.scan_schedule || "Nicht konfiguriert"}
            icon={<RefreshCw size={14} color={T.text3} />}
            editMode={editSchedule}
            onEdit={() => { setEditSchedule(true); setSchedule(tenant.scan_schedule || ""); }}
            onCancel={() => setEditSchedule(false)}
            onSave={handleSaveSchedule}
            saving={saving}
          >
            <select
              value={schedule}
              onChange={e => setSchedule(e.target.value)}
              style={{
                background: T.bg3, border: `1px solid ${T.borderFocus}`, borderRadius: 6,
                padding: "8px 12px", fontFamily: T.fontSans, fontSize: 12, color: T.text0,
                outline: "none", width: 220, cursor: "pointer",
              }}
            >
              <option value="">Kein automatischer Scan</option>
              <option value="daily">Täglich</option>
              <option value="weekly">Wöchentlich</option>
              <option value="monthly">Monatlich</option>
            </select>
          </SettingRow>
        </div>
      </Card>

      {/* Tenant info (read-only) */}
      <Card>
        <CardHeader title="Tenant-Informationen" />
        <div style={{ padding: "20px 24px", display: "flex", flexDirection: "column", gap: 18 }}>
          <SettingRow label="Tenant-ID"     value={tenantId || "—"}                             icon={<Key    size={14} color={T.text3} />} readOnly />
          <SettingRow label="Tenant-Status" value={tenant.active ? "Aktiv" : "Inaktiv"}         icon={<Shield size={14} color={tenant.active ? T.accent : T.text3} />} readOnly />
        </div>
      </Card>

      {/* Asset summary */}
      <Card>
        <CardHeader title="Asset-Zusammenfassung" />
        <div style={{ padding: "20px 24px", display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
          {[
            { label: "Subdomains",   value: tenant.assets?.subdomains ?? "—" },
            { label: "Unique IPs",   value: tenant.assets?.ips         ?? "—" },
            { label: "Offene Ports", value: tenant.assets?.ports        ?? "—" },
            { label: "Services",     value: tenant.assets?.services     ?? "—" },
          ].map(item => (
            <div key={item.label}>
              <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3, marginBottom: 4 }}>{item.label}</div>
              <div style={{ fontFamily: T.font, fontSize: 22, fontWeight: 700, color: T.text0 }}>{item.value}</div>
            </div>
          ))}
        </div>
      </Card>

      {/* UI switch */}
      <Card>
        <CardHeader title="UI-Einstellungen" />
        <div style={{ padding: "16px 24px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <div style={{ fontFamily: T.fontSans, fontSize: 13, color: T.text0, marginBottom: 4 }}>Classic UI</div>
            <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>Zurück zur klassischen Ansicht wechseln</div>
          </div>
          <Btn onClick={() => { localStorage.setItem("easm_ui", "classic"); window.location.replace("/"); }}>
            Zur Classic UI
          </Btn>
        </div>
      </Card>
    </div>
  );
}

function SettingRow({ label, value, icon, editMode, onEdit, onCancel, onSave, saving, readOnly, children }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", gap: 12, paddingBottom: 18, borderBottom: `1px solid ${T.border}` }}>
      <div style={{ width: 20, marginTop: 2, flexShrink: 0 }}>{icon}</div>
      <div style={{ flex: 1 }}>
        <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.04em" }}>
          {label}
        </div>
        {editMode ? (
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {children}
            <Btn onClick={onSave} variant="primary" disabled={saving} style={{ padding: "7px 14px" }}>
              {saving ? "…" : "Speichern"}
            </Btn>
            <Btn onClick={onCancel} variant="ghost">Abbrechen</Btn>
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontFamily: T.font, fontSize: 12, color: T.text1 }}>{value}</span>
            {!readOnly && (
              <button onClick={onEdit} style={{
                background: "transparent", border: "none", color: T.text3,
                fontFamily: T.fontSans, fontSize: 11, cursor: "pointer",
                padding: 0, textDecoration: "underline",
              }}>Bearbeiten</button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
