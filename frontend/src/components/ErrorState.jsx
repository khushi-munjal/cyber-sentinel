import { AlertTriangle, RefreshCw } from "lucide-react";

/**
 * ErrorState — error display block.
 * Props:
 *   message  — error string
 *   onRetry  — optional callback for a retry button
 *   inline   — smaller inline version
 */
function ErrorState({ message, onRetry, inline = false }) {
  const text = message || "Something went wrong. Please try again.";

  if (inline) {
    return (
      <div className="error-inline">
        <AlertTriangle size={15} />
        <span>{text}</span>
        {onRetry && (
          <button type="button" className="btn-link" onClick={onRetry}>
            Retry
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="error-state">
      <div className="error-state-icon">
        <AlertTriangle size={32} />
      </div>
      <h3 className="error-state-title">Unable to load data</h3>
      <p className="error-state-message">{text}</p>
      {onRetry && (
        <button type="button" className="btn-secondary" onClick={onRetry}>
          <RefreshCw size={15} />
          Try Again
        </button>
      )}
    </div>
  );
}

export default ErrorState;
