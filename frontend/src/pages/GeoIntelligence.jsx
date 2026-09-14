import { Globe, Map, MapPin, ShieldAlert } from "lucide-react";
import GeoMap from "../components/GeoMap";

function GeoIntelligence({ analysis, onNavigate }) {
  const geo      = analysis?.geo_intelligence || {};
  const location = geo?.location;

  const hasLocation =
    location &&
    typeof location.latitude  === "number" &&
    typeof location.longitude === "number";

  if (!analysis) {
    return (
      <div className="page">
        <div className="page-header">
          <div>
            <p className="page-eyebrow">GEO INTELLIGENCE</p>
            <h2 className="page-title">Geo Intelligence</h2>
            <p className="page-desc">City-level infrastructure location mapping.</p>
          </div>
        </div>
        <div className="card card--empty">
          <Map size={36} />
          <h3>No geo data available</h3>
          <p>Analyze an email to populate Geo Intelligence.</p>
          <button type="button" className="btn-primary" onClick={() => onNavigate("analyze")}>
            Analyze Email
          </button>
        </div>
      </div>
    );
  }

  const city      = location?.city     || "Unavailable";
  const region    = location?.region   || "—";
  const country   = location?.country  || "—";
  const isp       = location?.isp      || "—";
  const precision = location?.precision || "City-level intelligence";
  const ipCount   = Number(geo?.ip_analysis?.total_ips ?? 0);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <p className="page-eyebrow">GEO INTELLIGENCE · {analysis.case_id}</p>
          <h2 className="page-title">Infrastructure Location</h2>
          <p className="page-desc">
            City-level infrastructure intelligence — not an exact physical
            sender location.
          </p>
        </div>
      </div>

      <div className="stats-row">
        <GeoStat icon={<MapPin size={17} />}     label="Detected City"  value={hasLocation ? city : "Unavailable"} />
        <GeoStat icon={<Globe size={17} />}      label="Country"        value={hasLocation ? country : "—"} />
        <GeoStat icon={<ShieldAlert size={17}/>} label="Source IPs"     value={ipCount} />
        <GeoStat icon={<Map size={17} />}        label="Precision"      value={hasLocation ? "CITY" : "N/A"} />
      </div>

      <div className="two-col-grid geo-layout">
        <div className="card geo-map-card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Geo Intelligence Map</h3>
              <p className="card-desc">City-level infrastructure visualization</p>
            </div>
            <MapPin size={16} className="card-header-icon" />
          </div>
          <GeoMap geo={geo} />
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Infrastructure Details</h3>
              <p className="card-desc">Metadata from analysis</p>
            </div>
          </div>
          <div className="field-list">
            <FieldRow label="City"            value={city} />
            <FieldRow label="Region"          value={region} />
            <FieldRow label="Country"         value={country} />
            <FieldRow label="Latitude"        value={hasLocation ? location.latitude  : "—"} />
            <FieldRow label="Longitude"       value={hasLocation ? location.longitude : "—"} />
            <FieldRow label="ISP"             value={isp} />
            <FieldRow label="Mode"            value={geo?.mode || (location?.demo_mode ? "DEMO" : "LIVE")} />
            <FieldRow label="Precision"       value={precision} />
          </div>
          <div className="geo-disclaimer-card">
            <ShieldAlert size={14} />
            <span>
              City-level infrastructure intelligence only. Does not infer exact
              physical sender location.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

function GeoStat({ icon, label, value }) {
  return (
    <div className="card">
      <div className="stat-card-icon">{icon}</div>
      <div className="stat-card-body">
        <span className="stat-card-value">{value}</span>
        <span className="stat-card-label">{label}</span>
      </div>
    </div>
  );
}

function FieldRow({ label, value }) {
  return (
    <div className="field-row">
      <span className="field-label">{label}</span>
      <span className="field-value">{String(value == null ? "—" : value)}</span>
    </div>
  );
}

export default GeoIntelligence;
