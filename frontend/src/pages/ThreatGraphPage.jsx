import { Activity, Network, ShieldAlert } from "lucide-react";
import ThreatGraph from "../components/ThreatGraph";

function ThreatGraphPage({ analysis, onNavigate }) {
  const graph      = analysis?.threat_graph;
  const statistics = graph?.statistics || {};
  const nodeCount  = Number(statistics?.node_count  ?? graph?.nodes?.length ?? 0);
  const edgeCount  = Number(statistics?.edge_count  ?? graph?.edges?.length ?? 0);
  const nodeTypes  = statistics?.node_types || {};
  const typeCount  = Object.keys(nodeTypes).length;

  if (!analysis) {
    return (
      <div className="page">
        <div className="page-header">
          <div>
            <p className="page-eyebrow">THREAT INTELLIGENCE GRAPH</p>
            <h2 className="page-title">Threat Graph</h2>
            <p className="page-desc">Entity relationship visualization.</p>
          </div>
        </div>
        <div className="card card--empty">
          <Network size={36} />
          <h3>No threat graph available</h3>
          <p>Analyze an email to generate the investigation graph.</p>
          <button type="button" className="btn-primary" onClick={() => onNavigate("analyze")}>
            Analyze Email
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <p className="page-eyebrow">THREAT INTELLIGENCE GRAPH · {analysis.case_id}</p>
          <h2 className="page-title">Threat Graph</h2>
          <p className="page-desc">
            Entity relationships extracted from:{" "}
            <em>{analysis.email?.subject || "Email Investigation"}</em>
          </p>
        </div>
      </div>

      <div className="stats-row">
        <GraphStat icon={<Network size={17} />}     label="Graph Nodes"   value={nodeCount} />
        <GraphStat icon={<Activity size={17} />}    label="Relationships" value={edgeCount} />
        <GraphStat icon={<ShieldAlert size={17} />} label="Entity Types"  value={typeCount} />
        <GraphStat icon={<Network size={17} />}     label="Graph Status"  value="Active" />
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Investigation Graph</h3>
            <p className="card-desc">Sender → Email → URLs / Domains / IPs → Geo</p>
          </div>
          <Network size={16} className="card-header-icon" />
        </div>
        <ThreatGraph graph={graph} />
      </div>

      {/* Relationships table */}
      {Array.isArray(graph?.edges) && graph.edges.length > 0 && (
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Detected Relationships</h3>
              <p className="card-desc">{graph.edges.length} relationship{graph.edges.length !== 1 ? "s" : ""}</p>
            </div>
          </div>
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Relationship</th>
                  <th>Target</th>
                </tr>
              </thead>
              <tbody>
                {graph.edges.map((edge, i) => (
                  <tr key={i}>
                    <td className="monospace">{edge.source || "—"}</td>
                    <td>
                      <span className="relation-type-tag">
                        {String(edge.relationship || "related_to").replaceAll("_", " ")}
                      </span>
                    </td>
                    <td className="monospace">{edge.target || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Entity composition */}
      {typeCount > 0 && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Entity Composition</h3>
            <p className="card-desc">Node types in the graph</p>
          </div>
          <div className="entity-grid">
            {Object.entries(nodeTypes).map(([type, count]) => (
              <div key={type} className="entity-card">
                <span className="entity-type">{String(type).toUpperCase()}</span>
                <strong className="entity-count">{count}</strong>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function GraphStat({ icon, label, value }) {
  return (
    <div className="card">
      <div className="stat-card-icon">{icon}</div>
      <div className="stat-card-body">
        <span className="stat-card-value">{value}</span>
        <span className="stat-card-label">{label}</span>
      </div>
    </div>
  );
}

export default ThreatGraphPage;
