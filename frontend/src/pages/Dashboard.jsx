import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle,
  Clock,
  FileSearch,
  Mail,
  RefreshCw,
  Shield,
  ShieldAlert,
  TrendingUp,
  Zap,
} from "lucide-react";
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

import { getAnalytics, getCases } from "../services/api";
import StatCard from "../components/StatCard";
import RiskBadge from "../components/RiskBadge";
import ErrorState from "../components/ErrorState";

const PIE_COLORS = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
};

function Dashboard({ analysis, onNavigate }) {
  const [analytics, setAnalytics] = useState(null);
  const [recentCases, setRecentCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const [analyticsData, casesData] = await Promise.all([
        getAnalytics(),
        getCases(),
      ]);
      setAnalytics(analyticsData);
      const cases = Array.isArray(casesData?.cases) ? casesData.cases : [];
      setRecentCases(cases.slice(0, 8));
    } catch (err) {
      setError(err?.message || "Could not connect to MailTrace AI backend.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadData(); }, []);

  const dist = analytics?.risk_distribution || {};
  const total = analytics?.total_cases || 0;
  const critical = dist.critical || 0;
  const high     = dist.high     || 0;
  const medium   = dist.medium   || 0;
  const low      = dist.low      || 0;
  const safe     = low;

  const pieData = [
    { name: "Critical", value: critical, color: PIE_COLORS.critical },
    { name: "High",     value: high,     color: PIE_COLORS.high },
    { name: "Medium",   value: medium,   color: PIE_COLORS.medium },
    { name: "Low",      value: low,      color: PIE_COLORS.low },
  ].filter((d) => d.value > 0);

  const barData = [
    { label: "Critical", count: critical },
    { label: "High",     count: high },
    { label: "Medium",   count: medium },
    { label: "Low",      count: low },
  ];

  const engine = analytics?.engine || {};

  const engineItems = [
    { label: "ML Detection",       key: "ml_detection" },
    { label: "Header Forensics",   key: "header_forensics" },
    { label: "IOC Extraction",     key: "ioc_extraction" },
    { label: "Geo Intelligence",   key: "geo_intelligence" },
    { label: "Threat Graph",       key: "threat_graph" },
    { label: "Forensic Reporting", key: "forensic_reporting" },
  ];

  return (
    <div className="page">
      {/* ── Page header ─────────────────────────────────────────── */}
      <div className="page-header">
        <div>
          <p className="page-eyebrow">SECURITY OPERATIONS CENTER</p>
          <h2 className="page-title">Threat Intelligence Dashboard</h2>
          <p className="page-desc">
            Real-time overview of email threat analysis, risk distribution,
            and detection engine status.
          </p>
        </div>
        <div className="page-header-actions">
          <button
            type="button"
            className="btn-secondary btn--sm"
            onClick={loadData}
            disabled={loading}
          >
            <RefreshCw size={14} className={loading ? "spin" : ""} />
            Refresh
          </button>
          <button
            type="button"
            className="btn-primary"
            onClick={() => onNavigate("analyze")}
          >
            <FileSearch size={15} />
            Analyze Email
          </button>
        </div>
      </div>

      {error && (
        <ErrorState
          message={error}
          onRetry={loadData}
          inline
        />
      )}

      {/* ── Stats row ──────────────────────────────────────────── */}
      <div className="stats-row">
        <StatCard
          icon={<Mail size={18} />}
          label="Total Analyzed"
          value={total}
          sub="All cases"
          variant="default"
        />
        <StatCard
          icon={<ShieldAlert size={18} />}
          label="Critical / High"
          value={critical + high}
          sub="Immediate action needed"
          variant={critical + high > 0 ? "danger" : "default"}
        />
        <StatCard
          icon={<AlertTriangle size={18} />}
          label="Medium Risk"
          value={medium}
          sub="Requires review"
          variant={medium > 0 ? "warning" : "default"}
        />
        <StatCard
          icon={<CheckCircle size={18} />}
          label="Low Risk / Safe"
          value={safe}
          sub="No immediate threat"
          variant={safe > 0 ? "success" : "default"}
        />
        <StatCard
          icon={<TrendingUp size={18} />}
          label="Threat Rate"
          value={total > 0 ? `${Math.round(((critical + high) / total) * 100)}%` : "—"}
          sub="High+ severity rate"
          variant="info"
        />
      </div>

      {/* ── Charts row ─────────────────────────────────────────── */}
      <div className="dashboard-grid">
        {/* Risk distribution pie */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Risk Distribution</h3>
              <p className="card-desc">Cases by severity level</p>
            </div>
            <Activity size={16} className="card-header-icon" />
          </div>
          {loading ? (
            <div className="chart-loading"><span className="loading-spinner" /></div>
          ) : total === 0 ? (
            <div className="chart-empty">No cases analyzed yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#111827",
                    border: "1px solid #1f2d42",
                    borderRadius: "8px",
                    color: "#e2e8f0",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
          {/* Legend */}
          <div className="pie-legend">
            {Object.entries(PIE_COLORS).map(([k, c]) => (
              <span key={k} className="pie-legend-item">
                <i style={{ background: c }} />
                {k.charAt(0).toUpperCase() + k.slice(1)}
              </span>
            ))}
          </div>
        </div>

        {/* Risk count bar chart */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Severity Breakdown</h3>
              <p className="card-desc">Case count by risk level</p>
            </div>
            <TrendingUp size={16} className="card-header-icon" />
          </div>
          {loading ? (
            <div className="chart-loading"><span className="loading-spinner" /></div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={barData} margin={{ top: 8, right: 8, left: -24, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2d42" />
                <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#64748b" }} />
                <YAxis tick={{ fontSize: 11, fill: "#64748b" }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    background: "#111827",
                    border: "1px solid #1f2d42",
                    borderRadius: "8px",
                    color: "#e2e8f0",
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {barData.map((entry) => (
                    <Cell
                      key={entry.label}
                      fill={PIE_COLORS[entry.label.toLowerCase()] || "#6366f1"}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Latest analysis result */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Latest Analysis</h3>
              <p className="card-desc">Most recent email investigation</p>
            </div>
            <FileSearch size={16} className="card-header-icon" />
          </div>
          {analysis ? (
            <div className="latest-analysis">
              <div className="latest-analysis-top">
                <div>
                  <p className="la-subject">{analysis.email?.subject || "Untitled Email"}</p>
                  <p className="la-sender">{analysis.email?.sender || "Unknown Sender"}</p>
                </div>
                <RiskBadge level={analysis.risk?.level} size="lg" />
              </div>
              <div className="la-score-row">
                <span>Risk Score</span>
                <strong>{Number(analysis.risk?.score || 0).toFixed(1)}</strong>
              </div>
              <div className="la-field-row">
                <span>Classification</span>
                <strong>{analysis.machine_learning?.display_name || analysis.risk?.primary_threat || "—"}</strong>
              </div>
              <div className="la-field-row">
                <span>Case ID</span>
                <code>{analysis.case_id || "—"}</code>
              </div>
              <div className="la-field-row">
                <span>IOCs Found</span>
                <strong>{analysis.iocs?.summary?.total_iocs ?? 0}</strong>
              </div>
              <button
                type="button"
                className="btn-ghost btn--sm la-view-btn"
                onClick={() => onNavigate("analyze")}
              >
                View Full Investigation <ArrowRight size={13} />
              </button>
            </div>
          ) : (
            <div className="card-empty">
              <Shield size={28} />
              <p>No analysis yet</p>
              <button
                type="button"
                className="btn-primary btn--sm"
                onClick={() => onNavigate("analyze")}
              >
                Start First Analysis
              </button>
            </div>
          )}
        </div>
      </div>

      {/* ── Recent Cases table ─────────────────────────────────── */}
      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Recent Investigations</h3>
            <p className="card-desc">
              {loading
                ? "Loading cases…"
                : `${recentCases.length} recent case${recentCases.length !== 1 ? "s" : ""}`}
            </p>
          </div>
          <button
            type="button"
            className="btn-ghost btn--sm"
            onClick={() => onNavigate("cases")}
          >
            View All <ArrowRight size={13} />
          </button>
        </div>

        {loading ? (
          <div className="table-loading">
            <span className="loading-spinner" />
            <span>Loading cases…</span>
          </div>
        ) : recentCases.length === 0 ? (
          <div className="card-empty">
            <Mail size={24} />
            <p>No cases recorded yet. Analyze an email to begin.</p>
          </div>
        ) : (
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Case ID</th>
                  <th>Subject</th>
                  <th>Sender</th>
                  <th>Score</th>
                  <th>Level</th>
                </tr>
              </thead>
              <tbody>
                {recentCases.map((c) => (
                  <tr
                    key={c.case_id}
                    className="data-table-row--clickable"
                    onClick={() => onNavigate("cases")}
                  >
                    <td className="monospace">{c.case_id}</td>
                    <td className="td-truncate">{c.subject || "—"}</td>
                    <td className="td-truncate">{c.sender || "—"}</td>
                    <td>
                      <span className="score-chip">
                        {c.risk_score != null ? Number(c.risk_score).toFixed(1) : "—"}
                      </span>
                    </td>
                    <td><RiskBadge level={c.risk_level} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Engine status ──────────────────────────────────────── */}
      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Detection Engine Status</h3>
            <p className="card-desc">Analysis modules reported by backend</p>
          </div>
          <Zap size={16} className="card-header-icon" />
        </div>
        <div className="engine-grid">
          {engineItems.map(({ label, key }) => {
            const active = engine[key] !== false;
            return (
              <div key={key} className={`engine-item ${active ? "engine-item--active" : "engine-item--inactive"}`}>
                <span className="engine-dot" />
                <span className="engine-label">{label}</span>
                <span className="engine-status-label">{active ? "Online" : "Offline"}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Quick nav ──────────────────────────────────────────── */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Quick Access</h3>
        </div>
        <div className="quick-nav">
          {[
            { id: "analyze",  label: "Email Analyzer",      desc: "Upload and investigate .eml files",            icon: <FileSearch size={18} /> },
            { id: "threat",   label: "Threat Intelligence",  desc: "View all detected threats",                   icon: <ShieldAlert size={18} /> },
            { id: "url",      label: "URL Analysis",         desc: "Inspect extracted URLs",                      icon: <Activity size={18} /> },
            { id: "geo",      label: "Geo Intelligence",     desc: "City-level infrastructure location",          icon: <Shield size={18} /> },
            { id: "graph",    label: "Threat Graph",         desc: "Entity relationship visualization",           icon: <Activity size={18} /> },
            { id: "reports",  label: "Forensic Reports",     desc: "Download PDF investigation reports",          icon: <FileSearch size={18} /> },
          ].map(({ id, label, desc, icon }) => (
            <button
              key={id}
              type="button"
              className="quick-nav-item"
              onClick={() => onNavigate(id)}
            >
              <div className="quick-nav-icon">{icon}</div>
              <div className="quick-nav-text">
                <strong>{label}</strong>
                <span>{desc}</span>
              </div>
              <ArrowRight size={14} className="quick-nav-arrow" />
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
