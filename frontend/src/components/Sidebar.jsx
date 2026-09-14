import {
  Activity,
  BarChart3,
  FileSearch,
  FileText,
  Globe,
  Link,
  Map,
  Network,
  Settings,
  Shield,
  ShieldAlert,
} from "lucide-react";

const NAV_ITEMS = [
  {
    group: "OPERATIONS",
    items: [
      { id: "dashboard",  label: "Dashboard",          icon: Activity },
      { id: "analyze",    label: "Email Analyzer",      icon: FileSearch },
      { id: "cases",      label: "Investigation Cases", icon: Shield },
      { id: "threat",     label: "Threat Intelligence", icon: ShieldAlert },
      { id: "url",        label: "URL Analysis",        icon: Link },
      { id: "geo",        label: "Geo Intelligence",    icon: Map },
      { id: "graph",      label: "Threat Graph",        icon: Network },
    ],
  },
  {
    group: "REPORTING",
    items: [
      { id: "analytics",  label: "Analytics",          icon: BarChart3 },
      { id: "reports",    label: "Forensic Reports",   icon: FileText },
    ],
  },
  {
    group: "SYSTEM",
    items: [
      { id: "settings",   label: "Settings",           icon: Settings },
    ],
  },
];

function Sidebar({ active, onNavigate }) {
  return (
    <aside className="sidebar">
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon">
          <Shield size={20} strokeWidth={2.2} />
        </div>
        <div className="sidebar-brand-text">
          <span className="sidebar-brand-name">MailTrace AI</span>
          <span className="sidebar-brand-sub">Threat Intelligence</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        {NAV_ITEMS.map(({ group, items }) => (
          <div className="sidebar-group" key={group}>
            <div className="sidebar-group-label">{group}</div>
            {items.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                type="button"
                className={`sidebar-item${active === id ? " sidebar-item--active" : ""}`}
                onClick={() => onNavigate(id)}
              >
                <Icon size={16} strokeWidth={active === id ? 2.2 : 1.8} />
                <span>{label}</span>
              </button>
            ))}
          </div>
        ))}
      </nav>

      {/* Bottom */}
      <div className="sidebar-footer">
        <div className="sidebar-engine-status">
          <span className="sidebar-pulse" />
          <div>
            <span className="sidebar-engine-label">Threat Engine</span>
            <span className="sidebar-engine-value">Online</span>
          </div>
        </div>
        <div className="sidebar-user">
          <div className="sidebar-user-avatar">SOC</div>
          <div className="sidebar-user-info">
            <span className="sidebar-user-name">Security Analyst</span>
            <span className="sidebar-user-role">Investigator</span>
          </div>
        </div>
      </div>
    </aside>
  );
}

export default Sidebar;
