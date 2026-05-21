import { T, alpha } from "../../theme";

const CATEGORY_COLORS = {
  email_saas: T.accent,
  cloud:      "var(--medium)",
  security:   "var(--info)",
  cdn:        T.text3,
  unknown:    "var(--critical)",
};

const CATEGORY_LABELS = {
  email_saas: "E-Mail SaaS",
  cloud:      "Cloud",
  security:   "Security",
  cdn:        "CDN",
  unknown:    "Unbekannt",
};

function ProviderRow({ name, category, ips }) {
  const color = CATEGORY_COLORS[category] ?? T.text3;
  return (
    <tr>
      <td style={{ padding: "8px 12px", fontFamily: T.fontSans, fontSize: 12, color: T.text1 }}>
        {name}
      </td>
      <td style={{ padding: "8px 12px" }}>
        <span style={{
          fontFamily: T.font, fontSize: 9, fontWeight: 700,
          color, background: alpha(color, 10),
          border: `1px solid ${alpha(color, 22)}`,
          padding: "2px 7px", borderRadius: 3,
          textTransform: "uppercase",
        }}>
          {CATEGORY_LABELS[category] ?? category}
        </span>
      </td>
      <td style={{ padding: "8px 12px", fontFamily: T.font, fontSize: 10, color: T.text3 }}>
        {ips?.length ?? 0} IPs
      </td>
    </tr>
  );
}

export function ProviderTable({ enrichedIps = [] }) {
  // Group by provider
  const byProvider = {};
  for (const ip of enrichedIps) {
    const key = ip.provider_name ?? "Unknown";
    const category = ip.provider_category ?? "unknown";
    if (!byProvider[key]) byProvider[key] = { name: key, category, ips: [] };
    byProvider[key].ips.push(ip.address);
  }
  const rows = Object.values(byProvider).sort((a, b) => {
    if (a.category === "unknown" && b.category !== "unknown") return -1;
    if (b.category === "unknown" && a.category !== "unknown") return 1;
    return (a.name ?? "").localeCompare(b.name ?? "");
  });

  if (!rows.length) {
    return (
      <div style={{ fontFamily: T.fontSans, fontSize: 12, color: T.text4, padding: "12px 0" }}>
        Keine Provider-Daten verfügbar.
      </div>
    );
  }

  return (
    <table style={{ width: "100%", borderCollapse: "collapse" }}>
      <thead>
        <tr style={{ borderBottom: `1px solid ${T.border}` }}>
          {["Provider", "Kategorie", "IPs"].map(h => (
            <th key={h} style={{
              padding: "6px 12px", textAlign: "left",
              fontFamily: T.fontSans, fontSize: 10, fontWeight: 600,
              color: T.text4, textTransform: "uppercase", letterSpacing: "0.05em",
            }}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map(r => (
          <ProviderRow key={r.name} {...r} />
        ))}
      </tbody>
    </table>
  );
}
