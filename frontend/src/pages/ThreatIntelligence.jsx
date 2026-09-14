import { Shield, ShieldAlert } from "lucide-react";
import RiskBadge from "../components/RiskBadge";

/**
 * Threat Intelligence page.
 * Reads data from the current analysis result stored in App state.
 * All data comes from the real /analyze response — nothing invented.
 */
function ThreatIntelligence({ analysis, onNavigate }) {
  if (!analysis) {
    return (
      <div className="page">
        <div className="page-header">
          <div>
            <p className="page-eyebrow">THREAT INTELLIGENCE</p>
            <h2 className="page-title">Threat Intelligence</h2>
            <p className="page-desc">Detailed threat indicators from email analysis.</p>
          </div>
        </div>
        <div className="card card--empty">
          <ShieldAlert size={36} />
          <h3>No threat data available</h3>
          <p>Analyze an email first to populate threat intelligence.</p>
          <button type="button" className="btn-primary" onClick={() => onNavigate("analyze")}>
            Analyze Email
          </button>
        </div>
      </div>
    );
  }

  const risk    = analysis.risk    || {};
  const ml      = analysis.machine_learning || {};
  const headers = analysis.headers  || {};
  const iocs    = analysis.iocs     || {};
  const urls    = Array.isArray(analysis.url_analysis)  ? analysis.url_analysis  : [];
  const ips     = Array.isArray(analysis.ip_analysis)   ? analysis.ip_analysis   : [];
  const content = analysis.content_analysis || {};
  const geo     = analysis.geo_intelligence || {};

  const reasons = Array.isArray(risk.reasons) ? risk.reasons : [];

  // Build a unified threat indicator list from all sources
  const indicators = [];

  // From risk reasons
  reasons.forEach((r) => {
    const msg  = typeof r === "string" ? r : (r?.message || r?.description || "Threat signal");
    const sev  = typeof r === "object" ? (r?.severity || "MEDIUM") : "MEDIUM";
    const cat  = typeof r === "object" ? (r?.category || r?.type || "Risk Signal") : "Risk Signal";
    indicators.push({ type: cat, description: msg, severity: sev, source: "Risk Engine" });
  });

  // From suspicious URLs
  urls.filter((u) => u?.suspicious || u?.is_suspicious).forEach((u) => {
    indicators.push({
      type: "Suspicious URL",
      description: u?.url || "Suspicious URL detected",
      severity: u?.risk_score >= 70 ? "HIGH" : "MEDIUM",
      source: "URL Analyzer",
    });
  });

  // From header anomalies
  if ((headers.anomaly_count || 0) > 0) {
    indicators.push({
      type: "Header Anomaly",
      description: headers.forensic_status || `${headers.anomaly_count} header anomaly/anomalies detected`,
      severity: headers.anomaly_count >= 3 ? "HIGH" : "MEDIUM",
      source: "Header Forensics",
    });
  }

  // ML
  if (ml.display_name && ml.display_name !== "Legitimate") {
    indicators.push({
      type: "ML Classification",
      description: `Email classified as "${ml.display_name}" with ${Number(ml.confidence_percent || 0).toFixed(1)}% confidence.`,
      severity: risk.level || "MEDIUM",
      source: "ML Detector",
    });
  }

  const totalIOCs = iocs?.summary?.total_iocs || 0;
  if (totalIOCs > 0) {
    indicators.push({
      type: "IOC Detected",
      description: `${totalIOCs} indicator(s) of compromise extracted.`,
      severity: totalIOCs > 5 ? "HIGH" : "MEDIUM",
      source: "IOC Extractor",
    });
  }

  // Suspicious IPs
  ips.filter((ip) => ip?.suspicious || ip?.is_suspicious).forEach((ip) => {
    indicators.push({
      type: "Suspicious IP",
      description: ip?.ip || ip?.address || "Suspicious IP detected",
      severity: "HIGH",
      source: "IP Analyzer",
    });
  });

  const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  indicators.sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <p className="page-eyebrow">THREAT INTELLIGENCE · {analysis.case_id}</p>
          <h2 className="page-title">Threat Intelligence</h2>
          <p className="page-desc">
            Threat indicators extracted from: <em>{analysis.email?.subject || "Email Investigation"}</em>
          </p>
        </div>
        <RiskBadge level={risk.level} size="lg" />
      </div>

      {/* Overview stats */}
      <div className="stats-row">
        <ThreatStat label="Risk Score"       value={Number(risk.score || 0).toFixed(1)} />
        <ThreatStat label="Risk Level"       value={<RiskBadge level={risk.level} size="lg" />} />
        <ThreatStat label="Total Indicators" value={indicators.length} />
        <ThreatStat label="Total IOCs"       value={totalIOCs} />
        <ThreatStat label="ML Classification" value={ml.display_name || "—"} />
      </div>

      {/* Indicators table */}
      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Threat Indicators</h3>
            <p className="card-desc">{indicators.length} indicator{indicators.length !== 1 ? "s" : ""} detected</p>
          </div>
          <ShieldAlert size={16} className="card-header-icon" />
        </div>
        {indicators.length === 0 ? (
          <div className="card-empty">
            <Shield size={28} />
            <p>No threat indicators found — email appears safe.</p>
          </div>
        ) : (
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Description</th>
                  <th>Severity</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {indicators.map((ind, i) => (
                  <tr key={i}>
                    <td><span className="threat-type-tag">{ind.type}</span></td>
                    <td>{ind.description}</td>
                    <td><RiskBadge level={ind.severity} /></td>
                    <td className="text-muted">{ind.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* IOC breakdown */}
      <div className="two-col-grid">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">IOC Summary</h3>
          </div>
          <div className="field-list">
            <FieldRow label="Total IOCs"    value={totalIOCs} />
            <FieldRow label="URLs"          value={(iocs.urls || []).length} />
            <FieldRow label="IP Addresses"  value={(iocs.ip_addresses || []).length} />
            <FieldRow label="Domains"       value={(iocs.domains || []).length} />
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Threat Context</h3>
          </div>
          <div className="field-list">
            <FieldRow label="Primary Threat"      value={risk.primary_threat || "—"} />
            <FieldRow label="Threat Detected"     value={risk.threat_detected ? "Yes" : "No"} />
            <FieldRow label="Header Anomalies"    value={headers.anomaly_count ?? "—"} />
            <FieldRow label="Forensic Status"     value={headers.forensic_status || "—"} />
            <FieldRow label="Geo City"            value={geo.location?.city || "—"} />
            <FieldRow label="Recommended Action"  value={risk.recommended_action || "—"} />
          </div>
        </div>
      </div>
    </div>
  );
}

function ThreatStat({ label, value }) {
  return (
    <div className="card threat-stat-card">
      <span className="threat-stat-label">{label}</span>
      <div className="threat-stat-value">{value}</div>
    </div>
  );
}

function FieldRow({ label, value }) {
  return (
    <div className="field-row">
      <span className="field-label">{label}</span>
      <span className="field-value">{value != null ? value : "—"}</span>
    </div>
  );
}

export default ThreatIntelligence;
