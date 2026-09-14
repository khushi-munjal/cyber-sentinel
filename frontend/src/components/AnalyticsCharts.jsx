import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const threatDistribution = [
  { name: "Phishing", samples: 20 },
  { name: "Spoofing", samples: 12 },
  { name: "BEC", samples: 12 },
  { name: "Credential Theft", samples: 12 },
  { name: "Financial Fraud", samples: 12 },
  { name: "OTP Fraud", samples: 12 },
  { name: "Account Takeover", samples: 12 },
  { name: "Social Engineering", samples: 12 },
  { name: "Malware Delivery", samples: 12 },
  { name: "Legitimate", samples: 12 },
];

const modelPerformance = [
  { metric: "Accuracy", value: 65 },
  { metric: "Macro Precision", value: 58 },
  { metric: "Macro Recall", value: 63 },
  { metric: "Macro F1", value: 60 },
];

const classPerformance = [
  {
    name: "Account Takeover",
    precision: 0,
    recall: 0,
    f1: 0,
  },
  {
    name: "BEC",
    precision: 50,
    recall: 50,
    f1: 50,
  },
  {
    name: "Credential Theft",
    precision: 100,
    recall: 67,
    f1: 80,
  },
  {
    name: "Financial Fraud",
    precision: 50,
    recall: 67,
    f1: 57,
  },
  {
    name: "Legitimate",
    precision: 100,
    recall: 100,
    f1: 100,
  },
  {
    name: "Malware Delivery",
    precision: 67,
    recall: 100,
    f1: 80,
  },
  {
    name: "OTP Fraud",
    precision: 100,
    recall: 100,
    f1: 100,
  },
  {
    name: "Phishing",
    precision: 50,
    recall: 50,
    f1: 50,
  },
  {
    name: "Social Engineering",
    precision: 0,
    recall: 0,
    f1: 0,
  },
  {
    name: "Spoofing",
    precision: 67,
    recall: 100,
    f1: 80,
  },
];

function AnalyticsCharts() {
  return (
    <div className="analytics-charts">
      <div className="analytics-grid">
        <div className="analytics-panel">
          <div className="analytics-panel-header">
            <div>
              <span className="analytics-eyebrow">
                DATASET DISTRIBUTION
              </span>

              <h3>Threat Class Samples</h3>

              <p>
                Distribution of the 128 curated email samples across
                10 MailTrace AI classes.
              </p>
            </div>
          </div>

          <div className="chart-container">
            <ResponsiveContainer width="100%" height={350}>
              <BarChart
                data={threatDistribution}
                margin={{
                  top: 10,
                  right: 10,
                  left: 0,
                  bottom: 70,
                }}
              >
                <CartesianGrid strokeDasharray="3 3" />

                <XAxis
                  dataKey="name"
                  angle={-35}
                  textAnchor="end"
                  interval={0}
                  height={80}
                />

                <YAxis allowDecimals={false} />

                <Tooltip />

                <Bar
                  dataKey="samples"
                  name="Samples"
                  radius={[5, 5, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="analytics-panel">
          <div className="analytics-panel-header">
            <div>
              <span className="analytics-eyebrow">
                MODEL PERFORMANCE
              </span>

              <h3>Evaluation Metrics</h3>

              <p>
                Current test-set evaluation from the trained
                10-class classifier.
              </p>
            </div>
          </div>

          <div className="chart-container">
            <ResponsiveContainer width="100%" height={350}>
              <BarChart
                data={modelPerformance}
                margin={{
                  top: 10,
                  right: 10,
                  left: 0,
                  bottom: 15,
                }}
              >
                <CartesianGrid strokeDasharray="3 3" />

                <XAxis dataKey="metric" />

                <YAxis domain={[0, 100]} />

                <Tooltip />

                <Bar
                  dataKey="value"
                  name="Score (%)"
                  radius={[6, 6, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="analytics-panel full-width-analytics">
        <div className="analytics-panel-header">
          <div>
            <span className="analytics-eyebrow">
              CLASS-WISE ANALYSIS
            </span>

            <h3>Precision, Recall & F1-Score</h3>

            <p>
              Performance of the model across individual threat
              categories.
            </p>
          </div>
        </div>

        <div className="class-performance-table-wrapper">
          <table className="class-performance-table">
            <thead>
              <tr>
                <th>Threat Class</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1-Score</th>
              </tr>
            </thead>

            <tbody>
              {classPerformance.map((item) => (
                <tr key={item.name}>
                  <td>{item.name}</td>

                  <td>
                    <PerformanceValue value={item.precision} />
                  </td>

                  <td>
                    <PerformanceValue value={item.recall} />
                  </td>

                  <td>
                    <PerformanceValue value={item.f1} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="analytics-insight-grid">
        <div className="analytics-insight">
          <strong>Dataset Size</strong>
          <span>128 email samples</span>
        </div>

        <div className="analytics-insight">
          <strong>Training Set</strong>
          <span>102 samples</span>
        </div>

        <div className="analytics-insight">
          <strong>Testing Set</strong>
          <span>26 samples</span>
        </div>

        <div className="analytics-insight">
          <strong>Threat Classes</strong>
          <span>10 categories</span>
        </div>
      </div>
    </div>
  );
}

function PerformanceValue({ value }) {
  return (
    <div className="performance-value">
      <span>{value}%</span>

      <div className="performance-bar">
        <div
          className="performance-fill"
          style={{
            width: `${value}%`,
          }}
        />
      </div>
    </div>
  );
}

export default AnalyticsCharts;