import { useState } from "react";
import { toast } from "sonner";
import { Settings, Globe, Shield, Calendar, RefreshCw, Key } from "lucide-react";
import { T, alpha } from "../theme";
import { Card, CardHeader, KpiCard, PageLoading, Btn } from "../components/ui/index";
import { useApp } from "../context/AppContext";
import { apiFetch } from "../api/client";

export default function SettingsPage() {
  const { tenant, loading, reload, tenantId } = useApp();
  const [saving, setSaving]   = useState(false);
  const [domain, setDomain]   = useState("");
  const [schedule, setSchedule] = useState("");
  const [editDomain, setEditDomain]     = useState(false);
  const [editSchedule, setEditSchedule] = useState(false);

  if (loading) return <PageLoading />;

  const lastScanStr = tenant.last_scan
    ? new Date(tenant.last_scan).toLocaleString("de-DE", { dateStyle: "medium", timeStyle: "short" })
    : "Noch kein Scan";
  const nextScanStr = tenant.next_scan
    ? new Date(tenant.next_scan).toLocaleString("de-DE", { dateStyle: "medium", timeStyle: "short" })
    : "—";

  const handleSaveDomain = async () => {
    if (!domain.trim()) return;
    setSaving(true);
    try {
      // List existing domains to decide create vs update
      const existing = await apiFetch(`/tenants/${tenantId}/domains`);
      const domains  = existing.domains ?? existing;
      if (domains.length > 0) {
        await apiFetch(`/tenants/${tenantId}/domains/${domains[0].id}`, {
          method: "PATCH", body: { domain: domain.trim() },
        });
      } else {
        await apiFetch(`/tenants/${tenantId}/domains`, {
          method: "POST", body: { domain: domain.trim() },
        });
      }
      toast.success("Domain gespeichert");
      setEditDomain(false);
      setDomain("");
      reload();
    } catch (e) {
      toast.error("Fehler", { description: e.message });
    } finally { setSaving(false); }
  };

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
    } catch (e) {
      toast.error("Fehler", { description: e.message });
    } finally { setSaving(false); }
  };

  const scoreColor = (tenant.score || 0) >= 70 ? T.accent : (tenant.score || 0) >= 40 ? T.medium : T.critical;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20, maxWidth: 900 }}>
      {/* Page title */}
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
        <KpiCard label="Risk Score" value={tenant.score ?? "—"} color={scoreColor} sub={`Grade ${tenant.grade || "?"}`} icon={Shield} />
        <KpiCard label="Letzter Scan" value={lastScanStr} icon={Calendar} />
        <KpiCard label="Nächster Scan" value={nextScanStr} color={T.accent} icon={RefreshCw} />
      </div>

      {/* Tenant info */}
      <Card>
        <CardHeader title="Tenant-Informationen" icon={<Globe size={15} color={T.text3} />} />
        <div style={{ padding: "20px 24px", display: "flex", flexDirection: "column", gap: 18 }}>
          {/* Domain */}
          <SettingRow
            label="Domain"
            value={tenant.domain || "—"}
            icon={<Globe size={14} color={T.text3} />}
            editMode={editDomain}
            onEdit={() => { setEditDomain(true); setDomain(tenant.domain || ""); }}
            onCancel={() => setEditDomain(false)}
            onSave={handleSaveDomain}
            saving={saving}
          >
            <input
              value={domain}
              onChange={e => setDomain(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleSaveDomain()}
              placeholder="z.B. beispiel.de"
              style={{
                background: T.bg3, border: `1px solid ${T.borderFocus}`, borderRadius: 6,
                padding: "8px 12px", fontFamily: T.font, fontSize: 12, color: T.text0,
                outline: "none", width: 280,
              }}
            />
          </SettingRow>

          {/* Scan schedule */}
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

          {/* Tenant ID (read-only) */}
          <SettingRow
            label="Tenant-ID"
            value={tenantId || "—"}
            icon={<Key size={14} color={T.text3} />}
            readOnly
          />

          {/* Status */}
          <SettingRow
            label="Tenant-Status"
            value={tenant.active ? "Aktiv" : "Inaktiv"}
            icon={<Shield size={14} color={tenant.active ? T.accent : T.text3} />}
            readOnly
          />
        </div>
      </Card>

      {/* Asset summary */}
      <Card>
        <CardHeader title="Asset-Zusammenfassung" />
        <div style={{ padding: "20px 24px", display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
          {[
            { label: "Subdomains", value: tenant.assets?.subdomains ?? "—" },
            { label: "Unique IPs", value: tenant.assets?.ips ?? "—" },
            { label: "Offene Ports", value: tenant.assets?.ports ?? "—" },
            { label: "Services", value: tenant.assets?.services ?? "—" },
          ].map(item => (
            <div key={item.label}>
              <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3, marginBottom: 4 }}>{item.label}</div>
              <div style={{ fontFamily: T.font, fontSize: 22, fontWeight: 700, color: T.text0 }}>{item.value}</div>
            </div>
          ))}
        </div>
      </Card>

      {/* UI Switch */}
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
            <Btn onClick={onCancel}>Abbrechen</Btn>
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
