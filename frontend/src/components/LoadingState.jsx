import { Shield } from "lucide-react";

/**
 * LoadingState — fullscreen / section loading indicator.
 * Props:
 *   message — optional string override
 *   inline  — if true, renders as a smaller inline block
 */
function LoadingState({ message = "Analyzing…", inline = false }) {
  if (inline) {
    return (
      <div className="loading-inline">
        <span className="loading-spinner" />
        <span>{message}</span>
      </div>
    );
  }

  return (
    <div className="loading-state">
      <div className="loading-icon">
        <Shield size={32} className="loading-pulse" />
      </div>
      <p className="loading-message">{message}</p>
      <div className="loading-dots">
        <span /><span /><span />
      </div>
    </div>
  );
}

export default LoadingState;
