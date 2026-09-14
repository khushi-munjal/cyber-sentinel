import {
  CalendarDays,
  ChevronRight,
  Menu,
  ShieldCheck,
} from "lucide-react";

function Topbar({ currentPage, onMenuClick }) {
  const today = new Date().toLocaleDateString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });

  return (
    <header className="topbar">
      <div className="topbar-left">
        <button
          type="button"
          className="mobile-menu-button"
          onClick={onMenuClick}
          aria-label="Open menu"
        >
          <Menu size={21} />
        </button>

        <div className="breadcrumb">
          <span>MailTrace AI</span>

          <ChevronRight size={14} />

          <strong>{currentPage}</strong>
        </div>
      </div>

      <div className="topbar-right">
        <div className="engine-chip">
          <span className="engine-dot"></span>
          <span>Threat Engine Online</span>
        </div>

        <div className="date-chip">
          <CalendarDays size={15} />
          <span>{today}</span>
        </div>

        <div className="security-chip">
          <ShieldCheck size={17} />
          <span>Secure Session</span>
        </div>
      </div>
    </header>
  );
}

export default Topbar;