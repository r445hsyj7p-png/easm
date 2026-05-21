import { useEffect, useRef, useState } from "react";
import { T } from "../../theme";

const NODE_COLORS = {
  domain:    "var(--accent)",
  provider:  "#f59e0b",
  ip:        "#6366f1",
  asn:       "#8b5cf6",
  mx_server: "#10b981",
};

const EDGE_COLORS = {
  SPF_INCLUDES:   "#f59e0b",
  HAS_MX:         "#10b981",
  RESOLVES_TO:    "#6366f1",
  BELONGS_TO:     "#8b5cf6",
  SPF_AUTHORIZES: "var(--accent)",
};

function Legend() {
  return (
    <div style={{
      display: "flex", gap: 14, flexWrap: "wrap",
      padding: "8px 12px",
      background: T.bg2, borderRadius: 6,
      border: `1px solid ${T.border}`,
      marginBottom: 10,
    }}>
      {Object.entries(NODE_COLORS).map(([type, color]) => (
        <div key={type} style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: color, flexShrink: 0 }} />
          <span style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text3, textTransform: "uppercase" }}>
            {type.replace("_", " ")}
          </span>
        </div>
      ))}
    </div>
  );
}

export function EmailGraph({ graphData }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [loadErr, setLoadErr] = useState(null);

  useEffect(() => {
    if (!containerRef.current || !graphData?.nodes?.length) return;

    let cancelled = false;
    import("cytoscape").then(({ default: cytoscape }) => {
      if (cancelled || !containerRef.current) return;
      if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null; }

      cyRef.current = cytoscape({
        container: containerRef.current,
        elements: [...graphData.nodes, ...graphData.edges],
        style: [
          {
            selector: "node",
            style: {
              "label": "data(label)",
              "font-family": "'JetBrains Mono', monospace",
              "font-size": "9px",
              "color": "#e2e8f0",
              "text-valign": "bottom",
              "text-margin-y": "4px",
              "text-wrap": "ellipsis",
              "text-max-width": "120px",
              "width": 28,
              "height": 28,
              "border-width": 1.5,
              "border-color": "#1e293b",
            },
          },
          ...Object.entries(NODE_COLORS).map(([type, color]) => ({
            selector: `node[type="${type}"]`,
            style: { "background-color": color },
          })),
          {
            selector: "node[type='domain']",
            style: { width: 42, height: 42, "font-size": "11px", "font-weight": 700 },
          },
          {
            selector: "edge",
            style: {
              "width": 1.5,
              "line-color": "#334155",
              "target-arrow-color": "#334155",
              "target-arrow-shape": "triangle",
              "curve-style": "bezier",
              "label": "data(label)",
              "font-size": "7px",
              "color": "#64748b",
              "font-family": "'JetBrains Mono', monospace",
              "text-rotation": "autorotate",
              "edge-text-rotation": "autorotate",
            },
          },
          ...Object.entries(EDGE_COLORS).map(([label, color]) => ({
            selector: `edge[label="${label}"]`,
            style: { "line-color": color, "target-arrow-color": color },
          })),
          {
            selector: ":selected",
            style: { "border-width": 3, "border-color": "var(--accent)" },
          },
        ],
        layout: {
          name: "cose",
          animate: false,
          idealEdgeLength: 80,
          nodeRepulsion: 800000,
          gravity: 0.25,
          numIter: 1000,
          nodeDimensionsIncludeLabels: true,
        },
        userZoomingEnabled: true,
        userPanningEnabled: true,
        minZoom: 0.2,
        maxZoom: 4,
      });
    }).catch(e => {
      if (!cancelled) setLoadErr(String(e));
    });

    return () => {
      cancelled = true;
      if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null; }
    };
  }, [graphData]);

  if (loadErr) {
    return (
      <div style={{ padding: 16, fontFamily: T.font, fontSize: 11, color: T.text4 }}>
        Graph-Visualisierung nicht verfügbar (cytoscape nicht geladen).
        <br />Führen Sie <code>npm install</code> im frontend-Verzeichnis aus.
      </div>
    );
  }

  if (!graphData?.nodes?.length) {
    return (
      <div style={{ padding: 24, textAlign: "center", fontFamily: T.fontSans, fontSize: 12, color: T.text4 }}>
        Keine Graph-Daten verfügbar.
      </div>
    );
  }

  return (
    <div>
      <Legend />
      <div
        ref={containerRef}
        style={{
          width: "100%", height: 480,
          background: T.bg2, borderRadius: 8,
          border: `1px solid ${T.border}`,
        }}
      />
      <div style={{ fontFamily: T.fontSans, fontSize: 10, color: T.text4, marginTop: 6 }}>
        {graphData.nodes.length} Knoten · {graphData.edges.length} Kanten · Scroll zum Zoomen
      </div>
    </div>
  );
}
