import { AlertTriangle, CheckCircle, ShieldAlert } from "lucide-react";
import RiskBadge from "./RiskBadge";

/**
 * RiskScore — full-featured risk score card with circular indicator,
 * coloured progress bar, level badge, and recommended action.
 */
function RiskScore({ score = 0, level = "UNKNOWN", recommendedAction }) {
  const s = Math.min(Math.max(Number(score) || 0, 0), 100);
  const normalised = String(level || "UNKNOWN").toUpperCase();

  const getColorVar = () => {
    switch (normalised) {
      case "CRITICAL": return "var(--risk-critical)";
      case "HIGH":     return "var(--risk-high)";
      case "MEDIUM":   return "var(--risk-medium)";
      case "LOW":      return "var(--risk-low)";
      default:         return "var(--risk-unknown)";
    }
  };

  const getIcon = () => {
    if (normalised === "CRITICAL" || normalised === "HIGH")
      return <ShieldAlert size={28} />;
    if (normalised === "MEDIUM")
      return <AlertTriangle size={28} />;
    return <CheckCircle size={28} />;
  };

  // SVG circle
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (s / 100) * circumference;

  return (
    <div className="risk-score-card">
      {/* Circular gauge */}
      <div className="risk-gauge">
        <svg viewBox="0 0 100 100" className="risk-gauge-svg">
          <circle
            cx="50" cy="50" r={radius}
            fill="none"
            stroke="var(--surface-3)"
            strokeWidth="8"
          />
          <circle
            cx="50" cy="50" r={radius}
            fill="none"
            stroke={getColorVar()}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            transform="rotate(-90 50 50)"
            style={{ transition: "stroke-dashoffset 0.8s ease" }}
          />
        </svg>
        <div className="risk-gauge-center">
          <span className="risk-gauge-value">{s.toFixed(0)}</span>
          <span className="risk-gauge-max">/100</span>
        </div>
      </div>

      {/* Text info */}
      <div className="risk-score-info">
        <div className="risk-score-icon" style={{ color: getColorVar() }}>
          {getIcon()}
        </div>
        <RiskBadge level={normalised} size="lg" />
        <span className="risk-score-label">Risk Score</span>
      </div>

      {/* Progress bar */}
      <div className="risk-progress-wrap">
        <div
          className="risk-progress-bar"
          style={{
            width: `${s}%`,
            background: getColorVar(),
          }}
        />
      </div>

      {/* Recommended action */}
      {recommendedAction && (
        <div className="risk-action">
          <span className="risk-action-label">Recommended Action</span>
          <span className="risk-action-text">{recommendedAction}</span>
        </div>
      )}
    </div>
  );
}

export default RiskScore;
