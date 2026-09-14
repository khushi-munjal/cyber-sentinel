/**
 * StatCard — metric card used across dashboard & page headers.
 *
 * Props:
 *   icon     — React node (lucide icon)
 *   label    — Card title / label
 *   value    — Primary value (number or string)
 *   sub      — Secondary description text
 *   variant  — "default" | "danger" | "warning" | "success" | "info"
 *   trend    — optional "+12%" style string shown in corner
 */
function StatCard({ icon, label, value, sub, variant = "default", trend }) {
  return (
    <div className={`stat-card stat-card--${variant}`}>
      <div className="stat-card-header">
        <div className="stat-card-icon">{icon}</div>
        {trend && <span className="stat-card-trend">{trend}</span>}
      </div>
      <div className="stat-card-body">
        <span className="stat-card-value">{value ?? "—"}</span>
        <span className="stat-card-label">{label}</span>
        {sub && <span className="stat-card-sub">{sub}</span>}
      </div>
    </div>
  );
}

export default StatCard;
