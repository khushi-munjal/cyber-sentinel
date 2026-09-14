import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  Download,
  FileSearch,
  Globe,
  Link,
  Mail,
  MapPin,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Tag,
} from "lucide-react";

import { analyzeEmail, openForensicReport } from "../services/api";
import FileUpload from "../components/FileUpload";
import RiskScore from "../components/RiskScore";
import RiskBadge from "../components/RiskBadge";
import LoadingState from "../components/LoadingState";
import EvidenceList from "../components/EvidenceList";

function EmailAnalyzer({ analysis, setAnalysis }) {
  const [file, setFile]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");

  async function handleAnalyze() {
    if (!file) { setError("Please select an .eml file first."); return; }
    setLoading(true);
    setError("");
    try {
      const data = await analyzeEmail(file);
      setAnalysis(data);
    } catch (err) {
      setError(err?.message || "Unable to connect to the MailTrace AI backend.");
    } finally {
      setLoading(false);
    }
  }

  function handleReset() {
    setFile(null);
    setAnalysis(null);
    setError("");
  }

  const score         = Number(analysis?.risk?.score ?? 0);
  const level         = analysis?.risk?.level ?? "UNKNOWN";
  const threatDetected = analysis?.risk?.threat_detected === true;

  // ─── Upload screen ──────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="page page--centered">
        <LoadingState message="Running MailTrace AI forensic analysis pipeline…" />
        <p className="loading-sub">This may take a few seconds.</p>
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="page">
        <div className="page-header">
          <div>
            <p className="page-eyebrow">FORENSIC ANALYSIS</p>
            <h2 className="page-title">Email Analyzer</h2>
            <p className="page-desc">
              Upload an EML file to run the full MailTrace AI threat
              intelligence pipeline.
            </p>
          </div>
        </div>

        <div className="analyzer-layout">
          {/* Upload card */}
          <div className="card analyzer-upload-card">
            <div className="card-header">
              <div className="card-header-icon-circle">
                <Mail size={18} />
              </div>
              <div>
                <h3 className="card-title">Email Evidence</h3>
                <p className="card-desc">Select an EML file to investigate</p>
              </div>
            </div>

            <FileUpload
              selectedFile={file}
              onFileSelect={(f) => { setFile(f); setError(""); }}
              disabled={loading}
            />

            {error && (
              <div className="inline-error">
                <AlertTriangle size={14} />
                <span>{error}</span>
              </div>
            )}

            <button
              type="button"
              className="btn-primary btn--full"
              onClick={handleAnalyze}
              disabled={!file || loading}
            >
              <FileSearch size={16} />
              Run Forensic Analysis
            </button>
          </div>

          {/* Coverage card */}
          <div className="card">
            <div className="card-header">
              <div className="card-header-icon-circle">
                <Shield size={18} />
              </div>
              <div>
                <h3 className="card-title">Analysis Coverage</h3>
                <p className="card-desc">8-layer threat intelligence pipeline</p>
              </div>
            </div>
            <div className="coverage-list">
              {[
                ["Machine Learning",    "10-class email threat classification"],
                ["Header Forensics",    "SPF, DKIM, DMARC & identity anomalies"],
                ["IOC Extraction",      "URLs, IPs, domains, hashes"],
                ["URL Intelligence",    "Suspicious URL & domain indicators"],
                ["IP Analysis",         "Reputation & infrastructure data"],
                ["Content Analysis",    "Fraud & social-engineering patterns"],
                ["Geo Intelligence",    "City-level infrastructure mapping"],
                ["Forensic Reporting",  "Evidence-backed PDF report"],
              ].map(([title, desc]) => (
                <div key={title} className="coverage-item">
                  <CheckCircle size={14} className="coverage-check" />
                  <div>
                    <strong>{title}</strong>
                    <span>{desc}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ─── Results screen ─────────────────────────────────────────────────────
  const urls       = Array.isArray(analysis.url_analysis)    ? analysis.url_analysis    : [];
  const ips        = Array.isArray(analysis.ip_analysis)     ? analysis.ip_analysis     : [];
  const iocUrls    = Array.isArray(analysis.iocs?.urls)      ? analysis.iocs.urls       : [];
  const iocIps     = Array.isArray(analysis.iocs?.ip_addresses) ? analysis.iocs.ip_addresses : [];
  const iocDomains = Array.isArray(analysis.iocs?.domains)   ? analysis.iocs.domains    : [];
  const content    = analysis.content_analysis               || {};
  const ml         = analysis.machine_learning               || {};
  const headers    = analysis.headers                        || {};
  const geo        = analysis.geo_intelligence?.location     || {};

  return (
    <div className="page">
      {/* ── Results header ─────────────────────────────────────── */}
      <div className="page-header">
        <div>
          <p className="page-eyebrow">ANALYSIS COMPLETE · {analysis.case_id}</p>
          <h2 className="page-title">
            {analysis.email?.subject || "Email Investigation"}
          </h2>
          <p className="page-desc">{analysis.email?.sender || "Unknown sender"}</p>
        </div>
        <div className="page-header-actions">
          <div className={`threat-flag ${threatDetected ? "threat-flag--active" : "threat-flag--clear"}`}>
            {threatDetected ? (
              <><ShieldAlert size={14} /> Threat Detected</>
            ) : (
              <><CheckCircle size={14} /> No Immediate Threat</>
            )}
          </div>
          <button type="button" className="btn-secondary" onClick={handleReset}>
            <RefreshCw size={14} />
            New Analysis
          </button>
          {analysis.forensic_report?.available && (
            <button
              type="button"
              className="btn-primary"
              onClick={() => openForensicReport(analysis.case_id)}
            >
              <Download size={14} />
              Download Report
            </button>
          )}
        </div>
      </div>

      {/* ── Top row: Risk + Summary ────────────────────────────── */}
      <div className="results-top-row">
        <RiskScore
          score={score}
          level={level}
          recommendedAction={analysis.risk?.recommended_action}
        />

        <div className="card result-summary-card">
          <div className="card-header">
            <h3 className="card-title">Email Summary</h3>
          </div>
          <div className="field-list">
            <FieldRow label="Sender"         value={analysis.email?.sender} />
            <FieldRow label="Receiver"       value={analysis.email?.receiver} />
            <FieldRow label="Subject"        value={analysis.email?.subject} />
            <FieldRow label="Date"           value={analysis.email?.date} />
            <FieldRow label="Reply-To"       value={analysis.email?.reply_to} />
            <FieldRow label="Return-Path"    value={analysis.email?.return_path} />
            <FieldRow label="Case ID"        value={analysis.case_id} mono />
            <FieldRow label="Primary Threat" value={analysis.risk?.primary_threat || "—"} />
          </div>
        </div>
      </div>

      {/* ── Metrics row ────────────────────────────────────────── */}
      <div className="metrics-row">
        <MetricCard
          icon={<Shield size={18} />}
          label="ML Classification"
          value={ml.display_name || "Unavailable"}
          sub={ml.confidence_percent != null ? `${Number(ml.confidence_percent).toFixed(1)}% confidence` : "No confidence data"}
          variant={ml.available === false ? "danger" : "default"}
        />
        <MetricCard
          icon={<AlertTriangle size={18} />}
          label="Header Anomalies"
          value={headers.anomaly_count ?? 0}
          sub={headers.forensic_status || "No forensic status"}
          variant={(headers.anomaly_count || 0) > 0 ? "warning" : "success"}
        />
        <MetricCard
          icon={<Tag size={18} />}
          label="Total IOCs"
          value={analysis.iocs?.summary?.total_iocs ?? 0}
          sub="Extracted indicators of compromise"
          variant={(analysis.iocs?.summary?.total_iocs || 0) > 0 ? "warning" : "default"}
        />
        <MetricCard
          icon={<MapPin size={18} />}
          label="Geo Location"
          value={geo.city || "Unavailable"}
          sub={[geo.region, geo.country].filter(Boolean).join(", ") || "No location data"}
          variant="info"
        />
      </div>

      {/* ── Forensic Evidence ──────────────────────────────────── */}
      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Forensic Evidence</h3>
            <p className="card-desc">Risk factors contributing to the threat score</p>
          </div>
        </div>
        <EvidenceList
          reasons={analysis.risk?.reasons || []}
          evidence={analysis.risk?.evidence || []}
        />
      </div>

      {/* ── IOC + URL two-col ──────────────────────────────────── */}
      <div className="two-col-grid">
        {/* URLs */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">URL Analysis</h3>
              <p className="card-desc">{urls.length || iocUrls.length} URL{(urls.length || iocUrls.length) !== 1 ? "s" : ""} extracted</p>
            </div>
            <Link size={16} className="card-header-icon" />
          </div>
          {urls.length > 0 ? (
            <div className="ioc-list">
              {urls.map((u, i) => (
                <URLRow key={i} url={u} />
              ))}
            </div>
          ) : iocUrls.length > 0 ? (
            <div className="ioc-list">
              {iocUrls.slice(0, 10).map((u, i) => (
                <div key={i} className="ioc-item">
                  <Link size={13} />
                  <span className="ioc-value">{u}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="ioc-empty">No URLs extracted.</div>
          )}
        </div>

        {/* IP Analysis */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">IP &amp; Domain IOCs</h3>
              <p className="card-desc">{iocIps.length} IPs · {iocDomains.length} domains</p>
            </div>
            <Server size={16} className="card-header-icon" />
          </div>
          {ips.length > 0 ? (
            <div className="ioc-list">
              {ips.map((ip, i) => (
                <IPRow key={i} ip={ip} />
              ))}
            </div>
          ) : iocIps.length > 0 || iocDomains.length > 0 ? (
            <div className="ioc-list">
              {iocIps.map((ip, i) => (
                <div key={i} className="ioc-item">
                  <Server size={13} />
                  <span className="ioc-value">{ip}</span>
                  <span className="ioc-type-tag">IP</span>
                </div>
              ))}
              {iocDomains.map((d, i) => (
                <div key={`d${i}`} className="ioc-item">
                  <Globe size={13} />
                  <span className="ioc-value">{d}</span>
                  <span className="ioc-type-tag">Domain</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="ioc-empty">No IPs or domains extracted.</div>
          )}
        </div>
      </div>

      {/* ── Content analysis ───────────────────────────────────── */}
      {content && (
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Content Analysis</h3>
              <p className="card-desc">Linguistic and pattern signals detected in email body</p>
            </div>
          </div>
          <ContentAnalysisPanel content={content} />
        </div>
      )}

      {/* ── Action footer ──────────────────────────────────────── */}
      <div className="action-footer">
        <div className="action-footer-left">
          <strong>Recommended Action</strong>
          <p>{analysis.risk?.recommended_action || "Continue investigation."}</p>
        </div>
        <div className="action-footer-right">
          {analysis.forensic_report?.available && (
            <button
              type="button"
              className="btn-primary"
              onClick={() => openForensicReport(analysis.case_id)}
            >
              <Download size={15} />
              Download Forensic Report (PDF)
            </button>
          )}
          <button type="button" className="btn-secondary" onClick={handleReset}>
            <FileSearch size={15} />
            New Analysis
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function FieldRow({ label, value, mono = false }) {
  return (
    <div className="field-row">
      <span className="field-label">{label}</span>
      <span className={`field-value${mono ? " monospace" : ""}`}>{value || "—"}</span>
    </div>
  );
}

function MetricCard({ icon, label, value, sub, variant = "default" }) {
  return (
    <div className={`metric-card metric-card--${variant}`}>
      <div className="metric-card-icon">{icon}</div>
      <div className="metric-card-body">
        <span className="metric-card-label">{label}</span>
        <strong className="metric-card-value">{value}</strong>
        <span className="metric-card-sub">{sub}</span>
      </div>
    </div>
  );
}

function URLRow({ url }) {
  const obj = typeof url === "string" ? { url } : url;
  const riskScore = obj?.risk_score ?? obj?.score;
  const suspicious = obj?.suspicious || obj?.is_suspicious;
  const shortened  = obj?.is_shortened;
  const keywords   = Array.isArray(obj?.suspicious_keywords) ? obj.suspicious_keywords : [];

  return (
    <div className={`url-row ${suspicious ? "url-row--suspicious" : ""}`}>
      <div className="url-row-top">
        <Link size={13} className="url-icon" />
        <span className="url-value" title={obj?.url || String(url)}>
          {obj?.url || String(url)}
        </span>
        {riskScore != null && (
          <span className="url-score">{Number(riskScore).toFixed(0)}</span>
        )}
        {shortened && <span className="url-tag url-tag--shortened">Shortened</span>}
        {suspicious && <span className="url-tag url-tag--suspicious">Suspicious</span>}
      </div>
      {keywords.length > 0 && (
        <div className="url-keywords">
          {keywords.map((kw) => (
            <span key={kw} className="url-keyword">{kw}</span>
          ))}
        </div>
      )}
    </div>
  );
}

function IPRow({ ip }) {
  const obj = typeof ip === "string" ? { ip } : ip;
  const suspicious = obj?.suspicious || obj?.is_suspicious || obj?.is_private === false;

  return (
    <div className={`ioc-item ${suspicious ? "ioc-item--suspicious" : ""}`}>
      <Server size={13} />
      <span className="ioc-value">{obj?.ip || obj?.address || String(ip)}</span>
      {obj?.country && <span className="ioc-meta">{obj.country}</span>}
      {suspicious && <span className="ioc-type-tag ioc-type-tag--warn">Suspicious</span>}
    </div>
  );
}

function ContentAnalysisPanel({ content }) {
  const flags = [];

  if (content?.urgency_indicators?.length)
    flags.push({ label: "Urgency Indicators", items: content.urgency_indicators });
  if (content?.financial_keywords?.length)
    flags.push({ label: "Financial Keywords", items: content.financial_keywords });
  if (content?.credential_patterns?.length)
    flags.push({ label: "Credential Patterns", items: content.credential_patterns });
  if (content?.social_engineering?.length)
    flags.push({ label: "Social Engineering", items: content.social_engineering });

  const score = content?.risk_score ?? content?.score;

  if (flags.length === 0 && score == null) {
    return <p className="ioc-empty">No notable content signals detected.</p>;
  }

  return (
    <div className="content-analysis-panel">
      {score != null && (
        <div className="content-score">
          <span>Content Risk Score</span>
          <strong>{Number(score).toFixed(1)}</strong>
        </div>
      )}
      <div className="content-flags">
        {flags.map(({ label, items }) => (
          <div key={label} className="content-flag-group">
            <span className="content-flag-label">{label}</span>
            <div className="content-flag-items">
              {items.slice(0, 8).map((item, i) => (
                <span key={i} className="content-keyword">{item}</span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default EmailAnalyzer;
