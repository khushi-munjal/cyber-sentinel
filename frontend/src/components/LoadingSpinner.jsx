import { LoaderCircle } from "lucide-react";

function LoadingSpinner({ message = "Processing..." }) {
  return (
    <div className="loading-overlay">
      <div className="loading-card">
        <div className="loading-icon">
          <LoaderCircle size={28} />
        </div>

        <strong>{message}</strong>

        <span>
          MailTrace AI forensic engine is analyzing the email.
        </span>
      </div>
    </div>
  );
}

export default LoadingSpinner;