import RiskBadge from "./RiskBadge";

/**
 * ThreatTable — reusable table for displaying case/threat lists.
 *
 * Props:
 *   rows        — array of case objects
 *   onSelect    — called with the row when a row is clicked
 *   loading     — boolean
 */
function ThreatTable({ rows = [], onSelect, loading = false }) {
  if (loading) {
    return (
      <div className="table-empty">
        <span className="table-spinner" />
        <span>Loading records…</span>
      </div>
    );
  }

  if (rows.length === 0) {
    return (
      <div className="table-empty">
        <span className="table-empty-icon">📭</span>
        <span>No records found.</span>
      </div>
    );
  }

  return (
    <div className="data-table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            <th>Case ID</th>
            <th>Subject</th>
            <th>Sender</th>
            <th>Receiver</th>
            <th>Risk Score</th>
            <th>Level</th>
            <th>Filename</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={row.case_id}
              onClick={() => onSelect && onSelect(row)}
              className={onSelect ? "data-table-row--clickable" : ""}
            >
              <td className="monospace">{row.case_id || "—"}</td>
              <td className="td-truncate">{row.subject || "—"}</td>
              <td className="td-truncate">{row.sender || "—"}</td>
              <td className="td-truncate">{row.receiver || "—"}</td>
              <td>
                <span className="score-chip">
                  {row.risk_score != null ? Number(row.risk_score).toFixed(1) : "—"}
                </span>
              </td>
              <td>
                <RiskBadge level={row.risk_level || "UNKNOWN"} />
              </td>
              <td className="td-truncate text-muted">{row.filename || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default ThreatTable;
