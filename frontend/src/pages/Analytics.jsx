import {
  BarChart3,
  Database,
  Target,
  TestTube,
  Layers3,
  Activity,
} from "lucide-react";

import AnalyticsCharts from "../components/AnalyticsCharts";

function Analytics() {
  return (
    <div className="page">
      <div className="page-header">
        <div>
          <p className="page-eyebrow">DATA ANALYSIS &amp; MODEL INTELLIGENCE</p>
          <h2 className="page-title">Analytics</h2>
          <p className="page-desc">
            Dataset composition and machine learning performance for the
            MailTrace AI detection engine.
          </p>
        </div>
      </div>

      <div className="stats-row">
        <AnalyticsStat icon={<Database size={18} />}  label="Dataset Samples"  value="128"  sub="Curated email records" />
        <AnalyticsStat icon={<Layers3 size={18} />}   label="Threat Classes"   value="10"   sub="Multi-class classification" />
        <AnalyticsStat icon={<TestTube size={18} />}  label="Training Samples" value="102"  sub="Model training set" />
        <AnalyticsStat icon={<Target size={18} />}    label="Test Accuracy"    value="65%"  sub="Current evaluation" />
      </div>

      <div className="two-col-grid">
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Dataset Overview</h3>
              <p className="card-desc">Curated dataset for prototype classifier</p>
            </div>
            <Database size={16} className="card-header-icon" />
          </div>
          <div className="field-list">
            <FieldRow label="Total Samples"  value="128" />
            <FieldRow label="Training Set"   value="102" />
            <FieldRow label="Testing Set"    value="26" />
            <FieldRow label="Classes"        value="10" />
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Model Evaluation</h3>
              <p className="card-desc">10-class classifier performance</p>
            </div>
            <Activity size={16} className="card-header-icon" />
          </div>
          <div className="field-list">
            <FieldRow label="Accuracy"         value="65%" />
            <FieldRow label="Macro Precision"  value="58%" />
            <FieldRow label="Macro Recall"     value="63%" />
            <FieldRow label="Macro F1-Score"   value="60%" />
          </div>
        </div>
      </div>

      <AnalyticsCharts />

      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Analysis Methodology</h3>
            <p className="card-desc">How to interpret the current evaluation</p>
          </div>
          <BarChart3 size={16} className="card-header-icon" />
        </div>
        <div className="methodology-steps">
          {[
            ["01", "Dataset Preparation",   "Curated email text organized into 10 threat categories."],
            ["02", "Train / Test Split",     "102 training records and 26 testing records for prototype evaluation."],
            ["03", "Model Evaluation",       "Precision, recall, F1-score and accuracy assess class-wise performance."],
            ["04", "Hybrid Detection",       "ML is supplemented by header, IOC, URL, content and forensic signals."],
          ].map(([n, title, desc]) => (
            <div key={n} className="methodology-step">
              <span className="step-number">{n}</span>
              <div>
                <strong>{title}</strong>
                <p>{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card insight-note">
        <Activity size={18} />
        <div>
          <strong>Prototype Note</strong>
          <p>
            The dataset is intentionally small for proof-of-concept evaluation.
            Production deployment would require a substantially larger and more
            diverse dataset with broader real-world email coverage.
          </p>
        </div>
      </div>
    </div>
  );
}

function AnalyticsStat({ icon, label, value, sub }) {
  return (
    <div className="card analytics-stat">
      <div className="stat-card-icon">{icon}</div>
      <div className="stat-card-body">
        <span className="stat-card-value">{value}</span>
        <span className="stat-card-label">{label}</span>
        {sub && <span className="stat-card-sub">{sub}</span>}
      </div>
    </div>
  );
}

function FieldRow({ label, value }) {
  return (
    <div className="field-row">
      <span className="field-label">{label}</span>
      <span className="field-value">{value}</span>
    </div>
  );
}

export default Analytics;
