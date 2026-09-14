import {
  AlertTriangle,
  CheckCircle,
  ChevronRight,
  Clock3,
  FileSearch,
} from "lucide-react";

function CaseTable({ cases = [], onSelectCase }) {
  const getRiskClass = (level) => {
    return `case-risk case-risk-${String(
      level || "UNKNOWN"
    ).toLowerCase()}`;
  };

  const getThreatLabel = (item) => {
    if (item?.threat_type) {
      return item.threat_type;
    }

    if (item?.primary_threat) {
      return String(item.primary_threat)
        .replaceAll("_", " ")
        .replace(/\b\w/g, (char) => char.toUpperCase());
    }

    if (item?.risk_level === "LOW") {
      return "No Major Threat";
    }

    return "Unknown";
  };

  const formatDate = (value) => {
    if (!value) {
      return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return value;
    }

    return date.toLocaleString("en-IN", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  if (!Array.isArray(cases) || cases.length === 0) {
    return (
      <div className="case-table-empty">
        <FileSearch size={27} />

        <strong>No investigation cases yet</strong>

        <span>
          Analyze an email to create your first forensic case.
        </span>
      </div>
    );
  }

  return (
    <div className="case-table-wrapper">
      <div className="case-table-scroll">
        <table className="case-table">
          <thead>
            <tr>
              <th>Case ID</th>
              <th>Email</th>
              <th>Threat</th>
              <th>Risk Score</th>
              <th>Level</th>
              <th>Status</th>
              <th>Date</th>
              <th></th>
            </tr>
          </thead>

          <tbody>
            {cases.map((item, index) => {
              const score = Number(
                item?.risk_score ??
                  item?.score ??
                  item?.risk?.score ??
                  0
              );

              const level = String(
                item?.risk_level ??
                  item?.level ??
                  item?.risk?.level ??
                  "UNKNOWN"
              ).toUpperCase();

              const threatDetected =
                item?.threat_detected ??
                item?.risk?.threat_detected ??
                (level === "HIGH" || level === "CRITICAL");

              return (
                <tr
                  key={
                    item?.case_id ||
                    item?.id ||
                    `case-${index}`
                  }
                  onClick={() => onSelectCase?.(item)}
                >
                  <td>
                    <span className="case-id">
                      {item?.case_id || "—"}
                    </span>
                  </td>

                  <td>
                    <div className="case-email">
                      <strong>
                        {item?.subject || "Untitled Email"}
                      </strong>

                      <span>
                        {item?.sender || "Unknown Sender"}
                      </span>
                    </div>
                  </td>

                  <td>
                    <span className="case-threat">
                      {getThreatLabel(item)}
                    </span>
                  </td>

                  <td>
                    <strong className="case-score">
                      {score.toFixed(1)}
                    </strong>
                  </td>

                  <td>
                    <span className={getRiskClass(level)}>
                      {level}
                    </span>
                  </td>

                  <td>
                    <span
                      className={`case-status ${
                        threatDetected
                          ? "status-threat"
                          : "status-safe"
                      }`}
                    >
                      {threatDetected ? (
                        <>
                          <AlertTriangle size={13} />
                          Threat
                        </>
                      ) : (
                        <>
                          <CheckCircle size={13} />
                          Clear
                        </>
                      )}
                    </span>
                  </td>

                  <td>
                    <span className="case-date">
                      <Clock3 size={13} />
                      {formatDate(item?.created_at)}
                    </span>
                  </td>

                  <td>
                    <ChevronRight size={17} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default CaseTable;