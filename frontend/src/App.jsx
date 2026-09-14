import { useState } from "react";

import Sidebar            from "./components/Sidebar";
import Header             from "./components/Header";

import Dashboard          from "./pages/Dashboard";
import EmailAnalyzer      from "./pages/EmailAnalyzer";
import ThreatIntelligence from "./pages/ThreatIntelligence";
import URLAnalysis        from "./pages/URLAnalysis";
import InvestigationCases from "./pages/InvestigationCases";
import GeoIntelligence    from "./pages/GeoIntelligence";
import ThreatGraphPage    from "./pages/ThreatGraphPage";
import Analytics          from "./pages/Analytics";
import Reports            from "./pages/Reports";
import Settings           from "./pages/Settings";

// Page meta: used by the Header component
const PAGE_META = {
  dashboard: { title: "Dashboard",           subtitle: "Security Operations Center" },
  analyze:   { title: "Email Analyzer",      subtitle: "Forensic Analysis Pipeline" },
  threat:    { title: "Threat Intelligence", subtitle: "Detected Indicators" },
  url:       { title: "URL Analysis",        subtitle: "Extracted Link Intelligence" },
  cases:     { title: "Investigation Cases", subtitle: "Case Management" },
  geo:       { title: "Geo Intelligence",    subtitle: "Infrastructure Location" },
  graph:     { title: "Threat Graph",        subtitle: "Entity Relationships" },
  analytics: { title: "Analytics",           subtitle: "Model & Dataset Intelligence" },
  reports:   { title: "Forensic Reports",    subtitle: "PDF Investigation Reports" },
  settings:  { title: "Settings",            subtitle: "System Configuration" },
};

function App() {
  const [page,     setPage]     = useState("dashboard");
  const [analysis, setAnalysis] = useState(null);

  // Navigate and optionally attach analysis data (from case selection)
  function handleNavigate(newPage, analysisData) {
    setPage(newPage);
    if (analysisData !== undefined) {
      setAnalysis(analysisData);
    }
  }

  function handleSelectCase(caseData) {
    if (caseData?.analysis) setAnalysis(caseData.analysis);
    setPage("analyze");
  }

  const meta = PAGE_META[page] || PAGE_META.dashboard;

  const sharedProps = {
    analysis,
    onNavigate: handleNavigate,
  };

  function renderPage() {
    switch (page) {
      case "dashboard":
        return <Dashboard {...sharedProps} />;

      case "analyze":
        return (
          <EmailAnalyzer
            analysis={analysis}
            setAnalysis={setAnalysis}
          />
        );

      case "threat":
        return <ThreatIntelligence {...sharedProps} />;

      case "url":
        return <URLAnalysis {...sharedProps} />;

      case "cases":
        return <InvestigationCases onSelectCase={handleSelectCase} />;

      case "geo":
        return <GeoIntelligence {...sharedProps} />;

      case "graph":
        return <ThreatGraphPage {...sharedProps} />;

      case "analytics":
        return <Analytics />;

      case "reports":
        return <Reports analysis={analysis} onNavigate={handleNavigate} />;

      case "settings":
        return <Settings />;

      default:
        return <Dashboard {...sharedProps} />;
    }
  }

  return (
    <div className="app-shell">
      <Sidebar active={page} onNavigate={handleNavigate} />
      <div className="app-main">
        <Header title={meta.title} subtitle={meta.subtitle} />
        <div className="app-body">
          {renderPage()}
        </div>
      </div>
    </div>
  );
}

export default App;
