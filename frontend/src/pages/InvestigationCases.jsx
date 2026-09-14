import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  FileSearch,
  RefreshCw,
  Shield,
} from "lucide-react";

import { getCases } from "../services/api";
import CaseTable from "../components/CaseTable";
import ErrorState from "../components/ErrorState";

function InvestigationCases({ onSelectCase }) {
  const [cases, setCases]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState("");

  async function loadCases() {
    setLoading(true);
    setError("");
    try {
      const data = await getCases();
      setCases(Array.isArray(data?.cases) ? data.cases : Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err?.message || "Could not connect to the MailTrace AI backend.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadCases(); }, []);

  const total     = cases.length;
  const threats   = cases.filter((c) => ["HIGH","CRITICAL"].includes(String(c?.risk_level || "").toUpperCase())).length;
  const safeCases = cases.filter((c) => String(c?.risk_level || "").toUpperCase() === "LOW").length;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <p className="page-eyebrow">CASE MANAGEMENT</p>
          <h2 className="page-title">Investigation Cases</h2>
          <p className="page-desc">
            Review previously analyzed emails and their forensic results.
          </p>
        </div>
        <button
          type="button"
          className="btn-secondary"
          onClick={loadCases}
          disabled={loading}
        >
          <RefreshCw size={14} className={loading ? "spin" : ""} />
          Refresh
        </button>
      </div>

      <div className="stats-row">
        <CaseStat icon={<FileSearch size={17} />}      label="Total Cases"   value={total}     />
        <CaseStat icon={<AlertTriangle size={17} />}   label="Threat Cases"  value={threats}    variant={threats > 0 ? "danger" : "default"} />
        <CaseStat icon={<CheckCircle size={17} />}     label="Clear Cases"   value={safeCases}  variant={safeCases > 0 ? "success" : "default"} />
        <CaseStat icon={<Shield size={17} />}          label="Storage"       value="SQLite"    />
      </div>

      {error && <ErrorState message={error} onRetry={loadCases} inline />}

      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Case History</h3>
            <p className="card-desc">
              {loading
                ? "Loading records…"
                : `${total} case${total !== 1 ? "s" : ""} available`}
            </p>
          </div>
          <FileSearch size={16} className="card-header-icon" />
        </div>

        <CaseTable
          cases={cases}
          onSelectCase={onSelectCase}
        />

        {loading && (
          <div className="table-loading">
            <RefreshCw size={22} className="spin" />
            <span>Loading investigation cases…</span>
          </div>
        )}
      </div>
    </div>
  );
}

function CaseStat({ icon, label, value, variant = "default" }) {
  return (
    <div className={`card stat-card--${variant}`}>
      <div className="stat-card-icon">{icon}</div>
      <div className="stat-card-body">
        <span className="stat-card-value">{value}</span>
        <span className="stat-card-label">{label}</span>
      </div>
    </div>
  );
}

export default InvestigationCases;
