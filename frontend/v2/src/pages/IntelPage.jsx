import { useState } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import { T, SEV, SEV_ORDER, alpha } from "../theme";
import { Card, CardHeader, TH, TD, SevBadge, EmptyState, PageLoading, SearchInput, FilterPill } from "../components/ui/index";
import { useApp } from "../context/AppContext";

const SUB_TABS = [
  { id: "hosting",  label: "Hosting" },
  { id: "fqdn",     label: "FQDN-Inventar" },
  { id: "geo",      label: "Geo-Verteilung" },
  { id: "dns",      label: "DNS & E-Mail" },
];

const SEV_COLOR = { CRITICAL: T.critical, HIGH: T.high, MEDIUM: T.medium, LOW: T.low, INFO: T.info };

export default function IntelPage() {
  const { intel, loading } = useApp();
  const [sub, setSub] = useState("hosting");

  if (loading) return <PageLoading />;

  const fqdnCount = (intel?.fqdn_table || []).length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Sub-tabs */}
      <div style={{ display: "flex", gap: 0, borderBottom: `1px solid ${T.border}` }}>
        {SUB_TABS.map(t => (
          <button key={t.id} onClick={() => setSub(t.id)} style={{
            padding: "10px 18px", background: "transparent", border: "none",
            borderBottom: `2px solid ${sub === t.id ? T.accent : "transparent"}`,
            fontFamily: T.fontSans, fontSize: 13, fontWeight: sub === t.id ? 600 : 400,
            color: sub === t.id ? T.accent : T.text2, cursor: "pointer",
            transition: "color 0.12s", marginBottom: -1,
          }}>
            {t.id === "fqdn" ? `FQDN-Inventar (${fqdnCount})` : t.label}
          </button>
        ))}
      </div>

      {sub === "hosting" && <HostingTab intel={intel} />}
      {sub === "fqdn"    && <FqdnTab intel={intel} />}
      {sub === "geo"     && <GeoTab intel={intel} />}
      {sub === "dns"     && <DnsTab intel={intel} />}
    </div>
  );
}

/* ── Hosting tab ───────────────────────────────────────────────────────────── */
function HostingTab({ intel }) {
  const orgs = intel?.hosting_orgs || [];

  if (orgs.length === 0) {
    return (
      <Card>
        <EmptyState title="Keine Hosting-Daten" sub="Noch kein Scan mit RDAP-Auflösung durchgeführt." />
      </Card>
    );
  }

  const maxCount = Math.max(...orgs.map(o => o.count || o.asset_count || 1), 1);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      <Card>
        <CardHeader title="Hosting-Provider" sub={`${orgs.length} Organisationen`} />
        <div style={{ padding: "8px 0" }}>
          {orgs.slice(0, 20).map((o, i) => {
            const count   = o.count || o.asset_count || 1;
            const pct     = (count / maxCount) * 100;
            const riskCol = SEV_COLOR[o.risk] || T.info;
            return (
              <div key={i} style={{
                display: "flex", alignItems: "center", gap: 12,
                padding: "9px 18px", borderBottom: `1px solid ${T.border}`,
              }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                    <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {o.org || o.name || "Unbekannt"}
                    </div>
                    {o.asn && (
                      <span style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>AS{o.asn}</span>
                    )}
                  </div>
                  <div style={{ height: 3, background: T.bg4, borderRadius: 2, overflow: "hidden" }}>
                    <div style={{ width: `${pct}%`, height: "100%", background: riskCol, borderRadius: 2 }} />
                  </div>
                </div>
                <div style={{ flexShrink: 0, textAlign: "right", minWidth: 48 }}>
                  <div style={{ fontFamily: T.font, fontSize: 12, fontWeight: 700, color: riskCol }}>{count}</div>
                  <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>Assets</div>
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      <Card>
        <CardHeader title="Risiko nach Provider" />
        <div style={{ padding: "16px 20px", display: "flex", flexDirection: "column", gap: 10 }}>
          {["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(sev => {
            const count = orgs.filter(o => (o.risk || "INFO").toUpperCase() === sev).length;
            return count > 0 ? (
              <div key={sev} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <SevBadge sev={sev} small />
                <div style={{ flex: 1, height: 4, background: T.bg4, borderRadius: 2, overflow: "hidden" }}>
                  <div style={{ width: `${(count/orgs.length)*100}%`, height: "100%", background: SEV_COLOR[sev] || T.info, borderRadius: 2 }} />
                </div>
                <span style={{ fontFamily: T.font, fontSize: 11, fontWeight: 700, color: SEV_COLOR[sev] || T.info, minWidth: 20 }}>{count}</span>
              </div>
            ) : null;
          })}
        </div>
      </Card>
    </div>
  );
}

/* ── FQDN tab ──────────────────────────────────────────────────────────────── */
function FqdnTab({ intel }) {
  const [search, setSearch]   = useState("");
  const [sevFilter, setSev]   = useState("ALL");
  const [sort, setSort]       = useState({ col: "risk", dir: "asc" });

  const rows = (intel?.fqdn_table || [])
    .filter(r =>
      (sevFilter === "ALL" || r.risk === sevFilter) &&
      (!search || r.fqdn?.includes(search) || (r.ip||"").includes(search) || (r.org||"").toLowerCase().includes(search.toLowerCase()))
    )
    .sort((a, b) => {
      let cmp = 0;
      if (sort.col === "risk") cmp = (SEV_ORDER[a.risk] ?? 9) - (SEV_ORDER[b.risk] ?? 9);
      if (sort.col === "fqdn") cmp = (a.fqdn || "").localeCompare(b.fqdn || "");
      if (sort.col === "org")  cmp = (a.org  || "").localeCompare(b.org  || "");
      if (sort.col === "asn")  cmp = (a.asn  || 0) - (b.asn || 0);
      return sort.dir === "asc" ? cmp : -cmp;
    });

  const toggleSort = col => setSort(s => s.col === col ? { col, dir: s.dir === "asc" ? "desc" : "asc" } : { col, dir: "asc" });

  return (
    <Card>
      <CardHeader title="FQDN-Inventar" sub={`${rows.length} Einträge`} />
      <div style={{ display: "flex", gap: 8, alignItems: "center", padding: "10px 16px", borderBottom: `1px solid ${T.border}`, flexWrap: "wrap" }}>
        <SearchInput value={search} onChange={setSearch} placeholder="FQDN, IP, ASN, Organisation…" width={240} />
        <div style={{ width: 1, height: 20, background: T.border }} />
        <FilterPill label="Alle" active={sevFilter === "ALL"} onClick={() => setSev("ALL")} />
        {["CRITICAL","HIGH","MEDIUM","LOW"].map(s => (
          <FilterPill key={s} label={s} active={sevFilter === s}
            color={SEV[s]?.color} onClick={() => setSev(sevFilter === s ? "ALL" : s)} />
        ))}
      </div>
      {rows.length === 0 ? (
        <EmptyState title="Keine Einträge" sub="Noch kein Scan oder kein Ergebnis für diesen Filter." />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <TH onClick={() => toggleSort("fqdn")} sorted={sort.col === "fqdn"}>FQDN</TH>
                <TH>IP</TH>
                <TH>Land</TH>
                <TH onClick={() => toggleSort("org")} sorted={sort.col === "org"}>Organisation</TH>
                <TH onClick={() => toggleSort("asn")} sorted={sort.col === "asn"}>ASN</TH>
                <TH onClick={() => toggleSort("risk")} sorted={sort.col === "risk"}>Risiko</TH>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} style={{ transition: "background 0.1s" }}
                  onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                >
                  <TD style={{ fontFamily: T.font, fontSize: 11, color: T.accent }}>{r.fqdn || "—"}</TD>
                  <TD style={{ fontFamily: T.font, fontSize: 11, color: T.text2 }}>{r.ip   || "—"}</TD>
                  <TD style={{ fontFamily: T.font, fontSize: 11, color: T.text2 }}>{r.country || "—"}</TD>
                  <TD style={{ maxWidth: 200 }}>
                    <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.org || "—"}</div>
                  </TD>
                  <TD style={{ fontFamily: T.font, fontSize: 11, color: T.text3 }}>
                    {r.asn ? `AS${r.asn}` : "—"}
                  </TD>
                  <TD><SevBadge sev={r.risk || "INFO"} small /></TD>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

/* ── Geo tab ───────────────────────────────────────────────────────────────── */
function GeoTab({ intel }) {
  const geoAssets = intel?.geo_assets || [];

  if (geoAssets.length === 0) {
    return (
      <Card>
        <EmptyState title="Keine Geo-Daten" sub="Geo-Auflösung benötigt öffentliche IPv4-Adressen. Privat-IP oder kein Scan noch nicht durchgeführt." />
      </Card>
    );
  }

  const center = [geoAssets[0]?.lat || 30, geoAssets[0]?.lng || 10];

  const riskRadius = { CRITICAL: 14, HIGH: 11, MEDIUM: 8, LOW: 6, INFO: 5 };
  const riskColor  = { CRITICAL: T.critical, HIGH: T.high, MEDIUM: T.medium, LOW: T.low, INFO: T.info };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <Card>
        <CardHeader title="Geografische Verteilung" sub={`${geoAssets.length} Standorte`} />
        <style>{`
          .leaflet-container { background: #050810 !important; border-radius: 0 0 8px 8px; }
          .leaflet-control-attribution { background: rgba(5,8,16,0.85) !important; color: #273548 !important; font-size: 9px !important; }
          .leaflet-control-attribution a { color: #475569 !important; }
          .leaflet-control-zoom a { background: #0d1221 !important; border-color: #1e2d45 !important; color: #94a3b8 !important; }
          .leaflet-popup-content-wrapper { background: #0d1221 !important; border: 1px solid #1e2d45 !important; border-radius: 6px !important; color: #f1f5f9 !important; }
          .leaflet-popup-tip { background: #0d1221 !important; }
        `}</style>
        <MapContainer center={center} zoom={3} style={{ height: 360 }} scrollWheelZoom={false}>
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            attribution='&copy; <a href="https://carto.com">CARTO</a>'
          />
          {geoAssets.map((a, i) => (
            <CircleMarker
              key={i}
              center={[a.lat, a.lng]}
              radius={riskRadius[a.risk] || 6}
              pathOptions={{ color: riskColor[a.risk] || T.info, fillColor: riskColor[a.risk] || T.info, fillOpacity: 0.6, weight: 1.5 }}
            >
              <Popup>
                <div style={{ fontFamily: T.font, fontSize: 11, color: T.text0, lineHeight: 1.6 }}>
                  <strong style={{ color: riskColor[a.risk] }}>{a.city}, {a.country}</strong><br />
                  {a.ip_count} IP{a.ip_count !== 1 ? "s" : ""} &nbsp;·&nbsp; {a.risk}
                </div>
              </Popup>
            </CircleMarker>
          ))}
        </MapContainer>
      </Card>

      {/* Table */}
      <Card>
        <CardHeader title="Standorte" />
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <TH>Stadt</TH>
                <TH>Land</TH>
                <TH>IPs</TH>
                <TH>Risiko</TH>
              </tr>
            </thead>
            <tbody>
              {geoAssets.map((a, i) => (
                <tr key={i} style={{ transition: "background 0.1s" }}
                  onMouseEnter={e => e.currentTarget.style.background = T.bg3}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                >
                  <TD style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text0 }}>{a.city || "—"}</TD>
                  <TD style={{ fontFamily: T.font, fontSize: 11, color: T.text2 }}>{a.country || "—"}</TD>
                  <TD style={{ fontFamily: T.font, fontSize: 11, color: T.accent, fontWeight: 700 }}>{a.ip_count}</TD>
                  <TD><SevBadge sev={a.risk || "INFO"} small /></TD>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

/* ── DNS tab ───────────────────────────────────────────────────────────────── */
function DnsTab({ intel }) {
  const dns   = intel?.dns_info || {};
  const email = intel?.email_info || {};

  const dnsTypes = ["MX", "NS", "TXT", "SOA", "DMARC"];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      {/* DNS Records */}
      <Card>
        <CardHeader title="DNS-Records" />
        <div style={{ padding: "12px 0" }}>
          {dnsTypes.map(type => {
            const records = dns[type] || [];
            return (
              <div key={type} style={{ padding: "8px 18px", borderBottom: `1px solid ${T.border}` }}>
                <div style={{
                  display: "flex", alignItems: "center", gap: 8, marginBottom: records.length > 0 ? 6 : 0,
                }}>
                  <span style={{
                    fontFamily: T.font, fontSize: 9, fontWeight: 700, color: T.accent,
                    background: T.accent3, border: `1px solid ${alpha(T.accent, 19)}`,
                    padding: "1px 7px", borderRadius: 3, minWidth: 48, textAlign: "center",
                  }}>{type}</span>
                  {records.length === 0 && (
                    <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3 }}>Kein Eintrag</span>
                  )}
                </div>
                {records.map((r, i) => (
                  <div key={i} style={{
                    fontFamily: T.font, fontSize: 10, color: T.text1,
                    padding: "3px 6px", background: T.bg3, borderRadius: 3,
                    marginBottom: 3, wordBreak: "break-all", lineHeight: 1.5,
                  }}>{r}</div>
                ))}
              </div>
            );
          })}
        </div>
      </Card>

      {/* Email findings */}
      <Card>
        <CardHeader title="E-Mail & OSINT" />
        <div style={{ padding: "16px 20px" }}>
          {intel?.emails?.length > 0 ? (
            <>
              <div style={{ fontFamily: T.font, fontSize: 9, color: T.text4, letterSpacing: "0.08em", marginBottom: 8 }}>
                GEFUNDENE E-MAIL-ADRESSEN
              </div>
              {(intel.emails || []).map((e, i) => (
                <div key={i} style={{
                  fontFamily: T.font, fontSize: 11, color: T.low,
                  padding: "5px 8px", background: T.bg3, borderRadius: 3, marginBottom: 4,
                }}>{e}</div>
              ))}
            </>
          ) : (
            <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>
              Keine E-Mail-Adressen gefunden.
            </div>
          )}

          {intel?.subdomains_by_source && (
            <div style={{ marginTop: 20 }}>
              <div style={{ fontFamily: T.font, fontSize: 9, color: T.text4, letterSpacing: "0.08em", marginBottom: 8 }}>
                SUBDOMAIN-QUELLEN
              </div>
              {Object.entries(intel.subdomains_by_source).map(([src, cnt]) => (
                <div key={src} style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: `1px solid ${T.border}` }}>
                  <span style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text2 }}>{src}</span>
                  <span style={{ fontFamily: T.font, fontSize: 12, fontWeight: 700, color: T.accent }}>{cnt}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
