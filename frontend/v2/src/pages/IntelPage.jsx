import { useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Search, Shield, Mail, Settings2, AlertTriangle, CheckCircle, Eye, EyeOff } from "lucide-react";
import { T, alpha } from "../theme";
import { Card, CardHeader, EmptyState, Btn } from "../components/ui/index";
import { apiFetch } from "../api/client";
import { useApp } from "../context/AppContext";
import { toast } from "sonner";

const TABS = [
  { id: "ip-reputation", label: "IP Reputation",  Icon: Shield   },
  { id: "breaches",      label: "Breaches (HIBP)", Icon: Mail     },
  { id: "feed-settings", label: "Feed Settings",   Icon: Settings2},
];

const DEFAULT_FEEDS = [
  { id: "abuseipdb",    name: "AbuseIPDB",      description: "IP reputation & abuse reports", requiresKey: true,  enabled: false, key: "" },
  { id: "virustotal",   name: "VirusTotal",     description: "Multi-AV & URL scanner",        requiresKey: true,  enabled: false, key: "" },
  { id: "shodan",       name: "Shodan",         description: "Internet-wide port scanner",     requiresKey: true,  enabled: false, key: "" },
  { id: "hibp",         name: "HaveIBeenPwned", description: "Breach notification service",   requiresKey: true,  enabled: false, key: "" },
  { id: "otx",          name: "AlienVault OTX", description: "Open threat exchange",          requiresKey: true,  enabled: false, key: "" },
  { id: "greynoise",    name: "GreyNoise",      description: "Noise & benign scanner filter",  requiresKey: true,  enabled: false, key: "" },
  { id: "urlhaus",      name: "URLhaus",        description: "Malicious URL feed (free)",      requiresKey: false, enabled: true,  key: "" },
  { id: "feodo",        name: "Feodo Tracker",  description: "C2 botnet tracker (free)",       requiresKey: false, enabled: true,  key: "" },
];

export default function IntelPage() {
  const { tab: tabParam } = useParams();
  const navigate          = useNavigate();
  const activeTab         = TABS.find(t => t.id === tabParam)?.id || "ip-reputation";

  const go = id => navigate(`/intel/${id}`);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Header */}
      <div>
        <div style={{ fontFamily: T.fontSans, fontSize: 18, fontWeight: 700, color: T.text0, marginBottom: 4 }}>
          Intelligence
        </div>
        <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>
          IP Reputation, Breach-Daten und Threat-Feed-Konfiguration
        </div>
      </div>

      {/* Tab bar */}
      <div style={{ display: "flex", gap: 0, borderBottom: `1px solid ${T.border}` }}>
        {TABS.map(t => {
          const active = activeTab === t.id;
          return (
            <button key={t.id} onClick={() => go(t.id)} style={{
              display: "flex", alignItems: "center", gap: 6,
              padding: "10px 18px", background: "transparent", border: "none",
              borderBottom: `2px solid ${active ? T.accent : "transparent"}`,
              fontFamily: T.fontSans, fontSize: 13, fontWeight: active ? 600 : 400,
              color: active ? T.accent : T.text2, cursor: "pointer",
              transition: "color 0.12s", marginBottom: -1,
            }}>
              <t.Icon size={13} />{t.label}
            </button>
          );
        })}
      </div>

      {activeTab === "ip-reputation" && <IpReputationTab />}
      {activeTab === "breaches"      && <BreachesTab />}
      {activeTab === "feed-settings" && <FeedSettingsTab />}
    </div>
  );
}

/* ── IP Reputation ── */
function IpReputationTab() {
  const { tenantId } = useApp();
  const [ip,      setIp]      = useState("");
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState(null);
  const [error,   setError]   = useState(null);

  const lookup = useCallback(async () => {
    const target = ip.trim();
    if (!target) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const data = await apiFetch(`/tenants/${tenantId}/intel/ip-reputation?ip=${encodeURIComponent(target)}`);
      setResult(data);
    } catch (e) {
      if (e.message?.includes("404") || e.message?.includes("Method Not Allowed") || e.message?.includes("405")) {
        setError("Dieser Endpunkt ist noch nicht im Backend implementiert. Bitte API-Keys in den Feed Settings konfigurieren.");
      } else {
        setError(e.message);
      }
    } finally {
      setLoading(false);
    }
  }, [ip, tenantId]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Input */}
      <Card>
        <div style={{ padding: "20px 24px" }}>
          <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0, marginBottom: 12 }}>
            IP-Adresse nachschlagen
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              value={ip}
              onChange={e => setIp(e.target.value)}
              onKeyDown={e => e.key === "Enter" && lookup()}
              placeholder="z.B. 1.2.3.4"
              style={{
                flex: 1, padding: "9px 14px",
                background: T.bg3, border: `1px solid ${T.border}`,
                borderRadius: 6, fontFamily: T.font, fontSize: 12, color: T.text0,
                outline: "none",
              }}
            />
            <Btn onClick={lookup} variant="primary" disabled={loading || !ip.trim()}>
              <Search size={12} />
              {loading ? "Lädt…" : "Nachschlagen"}
            </Btn>
          </div>
          {error && (
            <div style={{ marginTop: 10, fontFamily: T.fontSans, fontSize: 12, color: T.critical }}>
              {error}
            </div>
          )}
        </div>
      </Card>

      {result && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          {/* AbuseIPDB panel */}
          <Card>
            <CardHeader title="AbuseIPDB" sub="Abuse Confidence Score" />
            <div style={{ padding: "16px 20px" }}>
              {result.abuseipdb ? (
                <AbusePanel data={result.abuseipdb} />
              ) : (
                <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>Kein API-Key konfiguriert.</div>
              )}
            </div>
          </Card>

          {/* VirusTotal panel */}
          <Card>
            <CardHeader title="VirusTotal" sub="Malicious / Suspicious Votes" />
            <div style={{ padding: "16px 20px" }}>
              {result.virustotal ? (
                <VtPanel data={result.virustotal} />
              ) : (
                <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>Kein API-Key konfiguriert.</div>
              )}
            </div>
          </Card>

          {/* Shodan / General */}
          {result.shodan && (
            <Card style={{ gridColumn: "1 / -1" }}>
              <CardHeader title="Shodan" sub="Open ports & banners" />
              <div style={{ padding: "16px 20px", display: "flex", flexWrap: "wrap", gap: 8 }}>
                {(result.shodan.ports || []).map(p => (
                  <span key={p} style={{
                    fontFamily: T.font, fontSize: 10, color: T.accent,
                    background: T.accent3, border: `1px solid ${alpha(T.accent, 25)}`,
                    padding: "2px 8px", borderRadius: 4,
                  }}>{p}</span>
                ))}
                {(!result.shodan.ports?.length) && (
                  <span style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>Keine offenen Ports gefunden.</span>
                )}
              </div>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function AbusePanel({ data }) {
  const score = data.abuseConfidenceScore ?? data.score ?? 0;
  const color = score >= 80 ? T.critical : score >= 40 ? T.high : score >= 10 ? T.medium : T.accent;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <div style={{
          width: 64, height: 64, borderRadius: "50%", flexShrink: 0,
          background: alpha(color, 12), border: `2px solid ${alpha(color, 40)}`,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontFamily: T.font, fontSize: 20, fontWeight: 700, color,
        }}>{score}</div>
        <div>
          <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text0, fontWeight: 600, marginBottom: 4 }}>
            Confidence Score
          </div>
          <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text2 }}>
            {score >= 80 ? "Hochgradig schädlich" : score >= 40 ? "Verdächtig" : score >= 10 ? "Leicht verdächtig" : "Unauffällig"}
          </div>
        </div>
      </div>
      {data.countryCode && (
        <Row label="Land"        value={data.countryCode} />
      )}
      {data.isp && (
        <Row label="ISP"         value={data.isp} />
      )}
      {data.totalReports != null && (
        <Row label="Reports"     value={data.totalReports} />
      )}
      {data.lastReportedAt && (
        <Row label="Letzter Report" value={new Date(data.lastReportedAt).toLocaleDateString("de-DE")} />
      )}
    </div>
  );
}

function VtPanel({ data }) {
  const stats    = data.last_analysis_stats || data.stats || {};
  const malicious = stats.malicious || 0;
  const suspicious= stats.suspicious || 0;
  const harmless  = stats.harmless || 0;
  const total     = malicious + suspicious + harmless + (stats.undetected || 0);
  const color     = malicious > 5 ? T.critical : malicious > 0 ? T.high : suspicious > 0 ? T.medium : T.accent;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div style={{ display: "flex", gap: 16 }}>
        <ScoreChip label="Malicious"  value={malicious}  color={T.critical} />
        <ScoreChip label="Suspicious" value={suspicious} color={T.medium}   />
        <ScoreChip label="Harmless"   value={harmless}   color={T.accent}   />
      </div>
      {total > 0 && (
        <div>
          <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3, marginBottom: 4 }}>
            ENGINES ({total} total)
          </div>
          <div style={{ height: 6, background: T.bg4, borderRadius: 3, overflow: "hidden", display: "flex" }}>
            <div style={{ width: `${(malicious/total)*100}%`,  height: "100%", background: T.critical }} />
            <div style={{ width: `${(suspicious/total)*100}%`, height: "100%", background: T.medium   }} />
            <div style={{ width: `${(harmless/total)*100}%`,   height: "100%", background: T.accent   }} />
          </div>
        </div>
      )}
      {data.country && <Row label="Land" value={data.country} />}
      {data.as_owner && <Row label="ASN Owner" value={data.as_owner} />}
    </div>
  );
}

function ScoreChip({ label, value, color }) {
  return (
    <div style={{ textAlign: "center" }}>
      <div style={{ fontFamily: T.font, fontSize: 18, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontFamily: T.font, fontSize: 9, color: T.text3 }}>{label.toUpperCase()}</div>
    </div>
  );
}

function Row({ label, value }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
      <span style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3 }}>{label}</span>
      <span style={{ fontFamily: T.font, fontSize: 11, color: T.text1 }}>{value}</span>
    </div>
  );
}

/* ── Breaches (HIBP) ── */
function BreachesTab() {
  const { tenantId } = useApp();
  const [email,   setEmail]   = useState("");
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState(null);
  const [error,   setError]   = useState(null);

  const lookup = useCallback(async () => {
    const target = email.trim();
    if (!target) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const data = await apiFetch(`/tenants/${tenantId}/intel/breaches?email=${encodeURIComponent(target)}`);
      setResult(data);
    } catch (e) {
      if (e.message?.includes("404") || e.message?.includes("Method Not Allowed") || e.message?.includes("405")) {
        setError("HIBP-Endpunkt noch nicht implementiert. Bitte HIBP API-Key in den Feed Settings hinterlegen.");
      } else {
        setError(e.message);
      }
    } finally {
      setLoading(false);
    }
  }, [email, tenantId]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <Card>
        <div style={{ padding: "20px 24px" }}>
          <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0, marginBottom: 4 }}>
            E-Mail auf Datenpannen prüfen
          </div>
          <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3, marginBottom: 12 }}>
            Powered by HaveIBeenPwned — API-Key erforderlich (Feed Settings)
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              value={email}
              onChange={e => setEmail(e.target.value)}
              onKeyDown={e => e.key === "Enter" && lookup()}
              placeholder="user@example.com"
              style={{
                flex: 1, padding: "9px 14px",
                background: T.bg3, border: `1px solid ${T.border}`,
                borderRadius: 6, fontFamily: T.font, fontSize: 12, color: T.text0,
                outline: "none",
              }}
            />
            <Btn onClick={lookup} variant="primary" disabled={loading || !email.trim()}>
              <Search size={12} />
              {loading ? "Lädt…" : "Prüfen"}
            </Btn>
          </div>
          {error && (
            <div style={{ marginTop: 10, fontFamily: T.fontSans, fontSize: 12, color: T.critical }}>
              {error}
            </div>
          )}
        </div>
      </Card>

      {result && (
        <>
          {result.breaches?.length > 0 ? (
            <>
              <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0 }}>
                {result.breaches.length} Datenpanne{result.breaches.length !== 1 ? "n" : ""} gefunden
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 12 }}>
                {result.breaches.map((b, i) => (
                  <BreachCard key={i} breach={b} />
                ))}
              </div>
            </>
          ) : (
            <Card>
              <div style={{
                padding: "32px 24px", display: "flex", alignItems: "center", justifyContent: "center",
                flexDirection: "column", gap: 10,
              }}>
                <CheckCircle size={32} color={T.accent} />
                <div style={{ fontFamily: T.fontSans, fontSize: 14, fontWeight: 600, color: T.text0 }}>
                  Keine Datenpannen gefunden
                </div>
                <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text3 }}>
                  {email} wurde in keiner bekannten Datenpanne gefunden.
                </div>
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

function BreachCard({ breach }) {
  const sevColor = breach.IsSensitive ? T.critical : breach.IsVerified ? T.high : T.medium;
  return (
    <div style={{
      background: T.bg2, border: `1px solid ${T.border}`,
      borderRadius: 8, padding: 16, borderTop: `2px solid ${alpha(sevColor, 50)}`,
    }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
        <div style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 700, color: T.text0 }}>
          {breach.Name || breach.name}
        </div>
        {breach.IsVerified && (
          <span style={{
            fontFamily: T.font, fontSize: 8, color: T.critical,
            background: T.criticalBg, border: `1px solid ${T.criticalBorder}`,
            padding: "1px 6px", borderRadius: 3, flexShrink: 0,
          }}>VERIFIED</span>
        )}
      </div>
      {breach.BreachDate && (
        <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3, marginBottom: 8 }}>
          {new Date(breach.BreachDate).toLocaleDateString("de-DE")}
          {breach.PwnCount && ` · ${(breach.PwnCount / 1e6).toFixed(1)}M Datensätze`}
        </div>
      )}
      {breach.DataClasses?.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
          {breach.DataClasses.slice(0, 6).map(c => (
            <span key={c} style={{
              fontFamily: T.font, fontSize: 8, color: sevColor,
              background: alpha(sevColor, 10), border: `1px solid ${alpha(sevColor, 25)}`,
              padding: "1px 6px", borderRadius: 3,
            }}>{c}</span>
          ))}
        </div>
      )}
      {breach.Description && (
        <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3, marginTop: 8, lineHeight: 1.5 }}>
          {breach.Description.replace(/<[^>]+>/g, "").slice(0, 160)}…
        </div>
      )}
    </div>
  );
}

/* ── Feed Settings ── */
function FeedSettingsTab() {
  const { tenantId } = useApp();
  const [feeds, setFeeds] = useState(DEFAULT_FEEDS);
  const [saving, setSaving] = useState(null);
  const [showKey, setShowKey] = useState({});

  const toggle = async (id) => {
    const feed = feeds.find(f => f.id === id);
    const next = !feed.enabled;
    setFeeds(fs => fs.map(f => f.id === id ? { ...f, enabled: next } : f));
    setSaving(id);
    try {
      await apiFetch(`/tenants/${tenantId}/intel/feeds/${id}`, {
        method: "PATCH", body: { enabled: next },
      });
    } catch (e) {
      if (!e.message?.includes("404") && !e.message?.includes("405")) {
        setFeeds(fs => fs.map(f => f.id === id ? { ...f, enabled: feed.enabled } : f));
        toast.error("Fehler beim Speichern", { description: e.message });
      }
      // 404/405 = backend not yet implemented; optimistic state stays
    } finally {
      setSaving(null);
    }
  };

  const saveKey = async (id, key) => {
    setSaving(id);
    try {
      await apiFetch(`/tenants/${tenantId}/intel/feeds/${id}`, {
        method: "PATCH", body: { api_key: key },
      });
      toast.success("API-Key gespeichert");
    } catch (e) {
      if (e.message?.includes("404") || e.message?.includes("405")) {
        toast.info("Feed-Endpunkt noch nicht verfügbar", { description: "Wird gespeichert sobald das Backend den Endpunkt bereitstellt." });
      } else {
        toast.error("Fehler", { description: e.message });
      }
    } finally {
      setSaving(null);
    }
  };

  const updateKey = (id, key) => setFeeds(fs => fs.map(f => f.id === id ? { ...f, key } : f));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <Card>
        <CardHeader title="Threat-Feed-Konfiguration" sub="API-Keys und Aktivierungsstatus der integrierten Threat Feeds" />
        <div>
          {feeds.map((feed, i) => (
            <div key={feed.id} style={{
              display: "flex", alignItems: "center", gap: 16,
              padding: "16px 20px",
              borderBottom: i < feeds.length - 1 ? `1px solid ${T.border}` : "none",
              transition: "background 0.1s",
            }}
              onMouseEnter={e => e.currentTarget.style.background = T.bg3}
              onMouseLeave={e => e.currentTarget.style.background = "transparent"}
            >
              {/* Toggle */}
              <button
                onClick={() => toggle(feed.id)}
                disabled={saving === feed.id}
                style={{
                  width: 36, height: 20, borderRadius: 10, border: "none", cursor: "pointer",
                  background: feed.enabled ? T.accent : T.bg4,
                  position: "relative", transition: "background 0.2s", flexShrink: 0,
                  opacity: saving === feed.id ? 0.6 : 1,
                }}
              >
                <div style={{
                  position: "absolute", top: 2,
                  left: feed.enabled ? 18 : 2,
                  width: 16, height: 16, borderRadius: "50%",
                  background: feed.enabled ? "var(--background)" : T.border2,
                  transition: "left 0.15s",
                }} />
              </button>

              {/* Info */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 2 }}>
                  <span style={{ fontFamily: T.fontSans, fontSize: 13, fontWeight: 600, color: T.text0 }}>
                    {feed.name}
                  </span>
                  {!feed.requiresKey && (
                    <span style={{
                      fontFamily: T.font, fontSize: 8, color: T.accent,
                      background: T.accent3, border: `1px solid ${alpha(T.accent, 25)}`,
                      padding: "0 5px", borderRadius: 3,
                    }}>FREE</span>
                  )}
                </div>
                <div style={{ fontFamily: T.fontSans, fontSize: 11, color: T.text3 }}>
                  {feed.description}
                </div>
              </div>

              {/* API Key input */}
              {feed.requiresKey && (
                <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                  <div style={{ position: "relative" }}>
                    <input
                      type={showKey[feed.id] ? "text" : "password"}
                      value={feed.key}
                      onChange={e => updateKey(feed.id, e.target.value)}
                      placeholder="API-Key eingeben…"
                      style={{
                        width: 220, padding: "7px 32px 7px 10px",
                        background: T.bg3, border: `1px solid ${T.border}`,
                        borderRadius: 6, fontFamily: T.font, fontSize: 11, color: T.text0,
                        outline: "none",
                      }}
                    />
                    <button
                      onClick={() => setShowKey(s => ({ ...s, [feed.id]: !s[feed.id] }))}
                      style={{
                        position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)",
                        background: "none", border: "none", color: T.text3, cursor: "pointer",
                        display: "flex", alignItems: "center",
                      }}
                    >
                      {showKey[feed.id] ? <EyeOff size={12} /> : <Eye size={12} />}
                    </button>
                  </div>
                  <Btn
                    onClick={() => saveKey(feed.id, feed.key)}
                    variant="secondary"
                    disabled={saving === feed.id || !feed.key.trim()}
                  >
                    {saving === feed.id ? "…" : "Speichern"}
                  </Btn>
                </div>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
