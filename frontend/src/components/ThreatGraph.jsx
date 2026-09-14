import {
  Mail,
  Globe,
  MapPin,
  Server,
  User,
  Link,
} from "lucide-react";

function ThreatGraph({ graph }) {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];

  const getNodeIcon = (type) => {
    switch (type) {
      case "sender":
      case "receiver":
        return <User size={15} />;

      case "email":
        return <Mail size={15} />;

      case "url":
        return <Link size={15} />;

      case "domain":
        return <Globe size={15} />;

      case "ip":
        return <Server size={15} />;

      case "geo":
        return <MapPin size={15} />;

      default:
        return <Globe size={15} />;
    }
  };

  const getNodeClass = (type) => {
    return `graph-node graph-node-${type || "unknown"}`;
  };

  if (!nodes.length) {
    return (
      <div className="threat-graph-empty">
        <Globe size={28} />
        <strong>No threat graph available</strong>
        <span>
          Analyze an email to generate relationships between entities.
        </span>
      </div>
    );
  }

  return (
    <div className="threat-graph-wrapper">
      <div className="graph-summary">
        <div>
          <span>Nodes</span>
          <strong>{nodes.length}</strong>
        </div>

        <div>
          <span>Relationships</span>
          <strong>{edges.length}</strong>
        </div>

        <div>
          <span>Entity Types</span>
          <strong>
            {new Set(nodes.map((node) => node.type)).size}
          </strong>
        </div>
      </div>

      <div className="graph-canvas">
        <div className="graph-lines">
          {edges.map((edge, index) => (
            <div
              className="graph-edge"
              key={`${edge.source}-${edge.target}-${index}`}
              title={`${edge.source} → ${edge.target}`}
            />
          ))}
        </div>

        <div className="graph-node-grid">
          {nodes.map((node, index) => (
            <div
              key={`${node.id}-${index}`}
              className={getNodeClass(node.type)}
            >
              <div className="graph-node-icon">
                {getNodeIcon(node.type)}
              </div>

              <div className="graph-node-content">
                <span className="graph-node-type">
                  {String(node.type || "entity").toUpperCase()}
                </span>

                <strong title={node.label}>
                  {node.label}
                </strong>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="graph-legend">
        <span>
          <i className="legend-dot legend-email"></i>
          Email
        </span>

        <span>
          <i className="legend-dot legend-url"></i>
          URL
        </span>

        <span>
          <i className="legend-dot legend-domain"></i>
          Domain
        </span>

        <span>
          <i className="legend-dot legend-ip"></i>
          IP
        </span>

        <span>
          <i className="legend-dot legend-geo"></i>
          Geo
        </span>
      </div>
    </div>
  );
}

export default ThreatGraph;