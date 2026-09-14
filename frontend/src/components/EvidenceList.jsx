import {
  AlertTriangle,
  CheckCircle,
  Info,
  ShieldAlert,
} from "lucide-react";

function EvidenceList({ reasons = [], evidence = [] }) {
  const getIcon = (severity) => {
    const level = String(severity || "").toUpperCase();

    if (level === "CRITICAL" || level === "HIGH") {
      return <ShieldAlert size={17} />;
    }

    if (level === "MEDIUM") {
      return <AlertTriangle size={17} />;
    }

    if (level === "LOW") {
      return <CheckCircle size={17} />;
    }

    return <Info size={17} />;
  };

  const getSeverityClass = (severity) => {
    const level = String(severity || "INFO").toLowerCase();
    return `severity-${level}`;
  };

  const getMessage = (reason) => {
    if (typeof reason === "string") {
      return reason;
    }

    return (
      reason?.message ||
      reason?.description ||
      "Evidence detected during analysis."
    );
  };

  const getCategory = (reason) => {
    if (typeof reason === "string") {
      return "Analysis Evidence";
    }

    return reason?.category || reason?.type || "Analysis Evidence";
  };

  const displayedReasons = Array.isArray(reasons) ? reasons : [];

  return (
    <div className="evidence-list-wrapper">
      {displayedReasons.length === 0 ? (
        <div className="no-evidence">
          <CheckCircle size={20} />
          <div>
            <strong>No suspicious evidence detected</strong>
            <span>
              The forensic engine did not identify major threat indicators.
            </span>
          </div>
        </div>
      ) : (
        <div className="evidence-list">
          {displayedReasons.map((reason, index) => {
            const severity =
              typeof reason === "object" && reason?.severity
                ? reason.severity
                : "INFO";

            return (
              <div
                className={`evidence-item ${getSeverityClass(severity)}`}
                key={`${getCategory(reason)}-${index}`}
              >
                <div className="evidence-icon">
                  {getIcon(severity)}
                </div>

                <div className="evidence-content">
                  <strong>{getCategory(reason)}</strong>

                  <span>{getMessage(reason)}</span>
                </div>

                <span className="evidence-severity">
                  {String(severity).toUpperCase()}
                </span>
              </div>
            );
          })}
        </div>
      )}

      {Array.isArray(evidence) && evidence.length > 0 && (
        <div className="evidence-signal-summary">
          <div className="signal-summary-header">
            <span>Evidence Sources</span>
            <strong>{evidence.length}</strong>
          </div>

          <div className="signal-summary-list">
            {evidence.map((item, index) => (
              <div className="signal-summary-item" key={index}>
                <span>
                  {item?.source || "Analysis Signal"}
                </span>

                <strong>
                  {item?.score_contribution !== undefined
                    ? `${item.score_contribution}`
                    : "Detected"}
                </strong>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default EvidenceList;