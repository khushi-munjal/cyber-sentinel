/**
 * RiskBadge — coloured severity label.
 * Accepts: CRITICAL | HIGH | MEDIUM | LOW | SAFE | UNKNOWN
 */
function RiskBadge({ level, size = "md" }) {
  const normalised = String(level || "UNKNOWN").toUpperCase();

  const variantMap = {
    CRITICAL: "risk-badge--critical",
    HIGH:     "risk-badge--high",
    MEDIUM:   "risk-badge--medium",
    LOW:      "risk-badge--low",
    SAFE:     "risk-badge--safe",
    UNKNOWN:  "risk-badge--unknown",
  };

  const cls = variantMap[normalised] || "risk-badge--unknown";

  return (
    <span className={`risk-badge risk-badge--${size} ${cls}`}>
      {normalised}
    </span>
  );
}

export default RiskBadge;
