import {
  AlertTriangle,
  CheckCircle,
  Globe,
  Link,
  Search,
  Shield,
} from "lucide-react";
import { useState } from "react";
import RiskBadge from "../components/RiskBadge";

/**
 * URL Analysis page.
 * Shows extracted URLs from the current analysis result.
 */
function URLAnalysis({ analysis, onNavigate }) {
  const [search, setSearch] = useState("");

  if (!analysis) {
    return (
      <div className="page">
        <div className="page-header">
          <div>
            <p className="page-eyebrow">URL ANALYSIS</p>
            <h2 className="page-title">URL Analysis</h2>
            <p className="page-desc">Inspect extracted URLs and their threat indicators.</p>
          </div>
        </div>
        <div className="card card--empty">
          <Link size={36} />
          <h3>No URL data available</h3>
          <p>Analyze an email to see extracted URLs and their analysis.</p>
          <button type="button" className="btn-primary" onClick={() => onNavigate("analyze")}>
            Analyze Email
          </button>
        </div>
      </div>
    );
  }

  // Prefer url_analysis array; fall back to raw ioc urls
  const rawUrls = Array.isArray(analysis.url_analysis)
    ? analysis.url_analysis
    : [];

  const iocUrls = Array.isArray(analysis.iocs?.urls)
    ? analysis.iocs.urls
    : [];

  // Build a normalised list
  const allUrls = rawUrls.length > 0
    ? rawUrls.map((u) =>
        typeof u === "string"
          ? { url: u, risk_score: null, suspicious: false, is_shortened: false, suspicious_keywords: [] }
          : u
      )
    : iocUrls.map((u) => ({ url: u, risk_score: null, suspicious: false, is_shortened: false, suspicious_keywords: [] }));

  const filtered = allUrls.filter((u) =>
    !search || (u.url || "").toLowerCase().includes(search.toLowerCase())
  );

  const suspicious  = allUrls.filter((u) => u.suspicious || u.is_suspicious);
  const shortened   = allUrls.filter((u) => u.is_shortened);
  const safe        = allUrls.filter((u) => !(u.suspicious || u.is_suspicious));

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <p className="page-eyebrow">URL ANALYSIS · {analysis.case_id}</p>
          <h2 className="page-title">URL Analysis</h2>
          <p className="page-desc">
            URLs extracted from: <em>{analysis.email?.subject || "Email"}</em>
          </p>
        </div>
      </div>

      {/* Stats */}
      <div className="stats-row">
        <URLStat icon={<Link size={17} />}          label="Total URLs"   value={allUrls.length}    />
        <URLStat icon={<AlertTriangle size={17} />}  label="Suspicious"   value={suspicious.length}  variant="danger" />
        <URLStat icon={<Globe size={17} />}          label="Shortened"    value={shortened.length}   variant="warning" />
        <URLStat icon={<CheckCircle size={17} />}    label="Appears Safe" value={safe.length}        variant="success" />
      </div>

      {/* Table */}
      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Extracted URLs</h3>
            <p className="card-desc">{allUrls.length} URL{allUrls.length !== 1 ? "s" : ""} found</p>
          </div>
          <div className="card-search">
            <Search size={14} />
            <input
              type="text"
              placeholder="Filter URLs…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>

        {allUrls.length === 0 ? (
          <div className="card-empty">
            <Shield size={28} />
            <p>No URLs extracted from this email.</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="card-empty">
            <p>No URLs match your search.</p>
          </div>
        ) : (
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Risk Score</th>
                  <th>Status</th>
                  <th>Shortened</th>
                  <th>Keywords</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((u, i) => {
                  const score      = u.risk_score != null ? Number(u.risk_score) : null;
                  const suspicious = u.suspicious || u.is_suspicious;
                  const shortened  = u.is_shortened;
                  const keywords   = Array.isArray(u.suspicious_keywords) ? u.suspicious_keywords : [];

                  const level = score == null
                    ? "UNKNOWN"
                    : score >= 80 ? "CRITICAL"
                    : score >= 60 ? "HIGH"
                    : score >= 40 ? "MEDIUM"
                    : "LOW";

                  return (
                    <tr key={i}>
                      <td className="url-cell">
                        <span className="url-cell-text" title={u.url}>{u.url}</span>
                      </td>
                      <td>
                        {score != null ? (
                          <span className="score-chip">{score.toFixed(0)}</span>
                        ) : (
                          <span className="text-muted">—</span>
                        )}
                      </td>
                      <td>
                        {suspicious ? (
                          <RiskBadge level={level} />
                        ) : (
                          <span className="status-safe-text">
                            <CheckCircle size={13} /> Safe
                          </span>
                        )}
                      </td>
                      <td>
                        {shortened ? (
                          <span className="url-tag url-tag--shortened">Yes</span>
                        ) : (
                          <span className="text-muted">No</span>
                        )}
                      </td>
                      <td>
                        <div className="keyword-chips">
                          {keywords.slice(0, 4).map((kw) => (
                            <span key={kw} className="url-keyword">{kw}</span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Domain / IP context from ioc */}
      {analysis.iocs?.domains?.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Extracted Domains</h3>
            <p className="card-desc">{analysis.iocs.domains.length} domain{analysis.iocs.domains.length !== 1 ? "s" : ""}</p>
          </div>
          <div className="ioc-list">
            {analysis.iocs.domains.map((d, i) => (
              <div key={i} className="ioc-item">
                <Globe size={13} />
                <span className="ioc-value">{d}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function URLStat({ icon, label, value, variant = "default" }) {
  return (
    <div className={`card url-stat-card stat-card--${variant}`}>
      <div className="stat-card-icon">{icon}</div>
      <div className="stat-card-body">
        <span className="stat-card-value">{value}</span>
        <span className="stat-card-label">{label}</span>
      </div>
    </div>
  );
}

export default URLAnalysis;
