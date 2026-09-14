import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  Cpu,
  Database,
  Globe,
  RefreshCw,
  Server,
  Shield,
  Wifi,
  WifiOff,
} from "lucide-react";
import { checkHealth, API_BASE_URL } from "../services/api";

function Settings() {
  const [status,  setStatus]  = useState("checking"); // checking | online | offline
  const [health,  setHealth]  = useState(null);
  const [loading, setLoading] = useState(false);

  async function checkConnection() {
    setLoading(true);
    setStatus("checking");
    setHealth(null);
    try {
      const data = await checkHealth();
      setHealth(data);
      setStatus("online");
    } catch {
      setStatus("offline");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { checkConnection(); }, []);

  const online = status === "online";

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <p className="page-eyebrow">SYSTEM CONFIGURATION</p>
          <h2 className="page-title">Settings</h2>
          <p className="page-desc">
            Monitor MailTrace AI system connectivity and detection engine
            configuration.
          </p>
        </div>
        <button
          type="button"
          className="btn-secondary"
          onClick={checkConnection}
          disabled={loading}
        >
          <RefreshCw size={14} className={loading ? "spin" : ""} />
          Check Connection
        </button>
      </div>

      {/* Connection banner */}
      <div className={`connection-banner ${online ? "connection-banner--online" : "connection-banner--offline"}`}>
        <div className="connection-banner-left">
          <div className="connection-banner-icon">
            {online ? <CheckCircle size={20} /> : <WifiOff size={20} />}
          </div>
          <div>
            <strong>
              Backend Status:{" "}
              {status === "checking" ? "Checking…" : status === "online" ? "Online" : "Offline"}
            </strong>
            <p>
              {online
                ? "MailTrace AI forensic backend is reachable and responding."
                : "Unable to reach the MailTrace AI backend. Ensure it is running on port 8001."}
            </p>
          </div>
        </div>
        <div className={`status-pill ${online ? "status-pill--online" : "status-pill--offline"}`}>
          {online ? <><span className="status-pulse-dot" /> Online</> : <><WifiOff size={12} /> Offline</>}
        </div>
      </div>

      {/* Config cards */}
      <div className="settings-grid">
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Backend Configuration</h3>
              <p className="card-desc">Current API connection</p>
            </div>
            <Server size={16} className="card-header-icon" />
          </div>
          <div className="field-list">
            <SettingRow icon={<Globe size={15} />}  label="API Base URL"       value={API_BASE_URL} mono />
            <SettingRow icon={<Server size={15} />} label="Port"               value="8001" />
            <SettingRow icon={<Wifi size={15} />}   label="Protocol"           value="HTTP" />
            <SettingRow icon={<Shield size={15} />} label="Environment"        value="Local Development" />
            <SettingRow
              icon={online ? <CheckCircle size={15} /> : <AlertTriangle size={15} />}
              label="Status"
              value={online ? "Connected" : "Disconnected"}
              valueClass={online ? "text-success" : "text-danger"}
            />
            {health?.timestamp && (
              <SettingRow icon={<Globe size={15} />} label="Last Checked" value={health.timestamp} />
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Detection Engine</h3>
              <p className="card-desc">Analysis pipeline components</p>
            </div>
            <Cpu size={16} className="card-header-icon" />
          </div>
          <div className="field-list">
            <SettingRow icon={<Cpu size={15} />}      label="ML Classifier"      value="10-Class Gradient Boost" />
            <SettingRow icon={<Shield size={15} />}   label="Risk Engine"        value="Hybrid Forensic" />
            <SettingRow icon={<Database size={15} />} label="Case Storage"       value="SQLite (local)" />
            <SettingRow icon={<Globe size={15} />}    label="Geo Intelligence"   value="City-Level" />
            <SettingRow icon={<Server size={15} />}   label="Report Format"      value="PDF (fpdf2)" />
            <SettingRow icon={<Cpu size={15} />}      label="API Framework"      value="FastAPI 3.0" />
          </div>
        </div>
      </div>

      {/* System health grid */}
      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">System Health</h3>
            <p className="card-desc">
              {health ? `Last response: ${health.timestamp || "—"}` : "No health data"}
            </p>
          </div>
          <div className={`status-pill ${online ? "status-pill--online" : "status-pill--offline"}`}>
            {online ? "Healthy" : "Unavailable"}
          </div>
        </div>
        <div className="health-grid">
          {[
            ["API Server",         "Operational",  "Unavailable"],
            ["Email Analyzer",     "Ready",        "Offline"],
            ["ML Classifier",      "Loaded",       "Offline"],
            ["Forensic Engine",    "Ready",        "Offline"],
            ["IOC Extractor",      "Ready",        "Offline"],
            ["Geo Intelligence",   "Configured",   "Offline"],
            ["Report Generator",   "Ready",        "Offline"],
            ["Database",           "Connected",    "Unknown"],
          ].map(([title, onVal, offVal]) => (
            <HealthItem key={title} title={title} value={online ? onVal : offVal} online={online} />
          ))}
        </div>

        {/* Raw health response */}
        {health && (
          <div className="health-response">
            <span className="health-response-label">Health endpoint response</span>
            <pre>{JSON.stringify(health, null, 2)}</pre>
          </div>
        )}
      </div>

      {/* Security note */}
      <div className="card security-note">
        <Shield size={18} />
        <div>
          <strong>Security &amp; Privacy</strong>
          <p>
            MailTrace AI is configured for local development. Email files are
            sent only to your local FastAPI backend running on{" "}
            <code>{API_BASE_URL}</code>. Geo intelligence reports city-level
            infrastructure location and does not claim an exact physical sender
            position.
          </p>
        </div>
      </div>
    </div>
  );
}

function SettingRow({ icon, label, value, mono = false, valueClass = "" }) {
  return (
    <div className="field-row">
      <span className="field-label field-label--icon">
        {icon}
        {label}
      </span>
      <span className={`field-value${mono ? " monospace" : ""} ${valueClass}`}>{value || "—"}</span>
    </div>
  );
}

function HealthItem({ title, value, online }) {
  return (
    <div className="health-item">
      <div className="health-item-header">
        <span className={`health-dot ${online ? "health-dot--online" : "health-dot--offline"}`} />
        <span className="health-item-title">{title}</span>
      </div>
      <span className={`health-item-value ${online ? "text-success" : "text-muted"}`}>
        {value}
      </span>
    </div>
  );
}

export default Settings;
