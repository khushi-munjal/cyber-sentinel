import { useEffect, useState } from "react";
import { Bell, CheckCircle, Search, WifiOff } from "lucide-react";
import { checkHealth } from "../services/api";

function Header({ title, subtitle }) {
  const [apiStatus, setApiStatus] = useState("checking"); // checking | online | offline
  const [notifOpen, setNotifOpen] = useState(false);

  useEffect(() => {
    let mounted = true;

    async function ping() {
      try {
        await checkHealth();
        if (mounted) setApiStatus("online");
      } catch {
        if (mounted) setApiStatus("offline");
      }
    }

    ping();
    const interval = setInterval(ping, 30000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <header className="topbar">
      {/* Page title */}
      <div className="topbar-title">
        <h1 className="topbar-page-title">{title}</h1>
        {subtitle && <span className="topbar-page-sub">{subtitle}</span>}
      </div>

      {/* Right controls */}
      <div className="topbar-controls">
        {/* Search */}
        <div className="topbar-search">
          <Search size={14} />
          <input type="text" placeholder="Search cases, threats…" />
        </div>

        {/* API status pill */}
        <div className={`api-status api-status--${apiStatus}`}>
          {apiStatus === "online" ? (
            <CheckCircle size={13} />
          ) : apiStatus === "offline" ? (
            <WifiOff size={13} />
          ) : (
            <span className="api-status-spinner" />
          )}
          <span>
            {apiStatus === "online"
              ? "API Online"
              : apiStatus === "offline"
              ? "API Offline"
              : "Connecting…"}
          </span>
        </div>

        {/* Notifications */}
        <button
          type="button"
          className="topbar-icon-btn"
          onClick={() => setNotifOpen(!notifOpen)}
          aria-label="Notifications"
        >
          <Bell size={17} />
          <span className="topbar-notif-dot" />
        </button>

        {/* User avatar */}
        <div className="topbar-avatar" title="Security Analyst">
          <span>SA</span>
        </div>
      </div>
    </header>
  );
}

export default Header;
