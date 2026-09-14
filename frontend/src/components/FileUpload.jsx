import { useRef, useState } from "react";
import {
  FileUp,
  Mail,
  ShieldCheck,
  AlertCircle,
  X,
} from "lucide-react";

function FileUpload({ onFileSelect, selectedFile, disabled = false }) {
  const inputRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);

  const validateFile = (file) => {
    if (!file) {
      return;
    }

    if (!file.name.toLowerCase().endsWith(".eml")) {
      alert("Please select a valid .eml email file.");
      return;
    }

    onFileSelect(file);
  };

  const handleInputChange = (event) => {
    const file = event.target.files?.[0];
    validateFile(file);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);

    if (disabled) {
      return;
    }

    const file = event.dataTransfer.files?.[0];
    validateFile(file);
  };

  const removeFile = (event) => {
    event.stopPropagation();

    if (inputRef.current) {
      inputRef.current.value = "";
    }

    onFileSelect(null);
  };

  const openFilePicker = () => {
    if (!disabled) {
      inputRef.current?.click();
    }
  };

  return (
    <div className="file-upload-wrapper">
      <input
        ref={inputRef}
        type="file"
        accept=".eml,message/rfc822"
        onChange={handleInputChange}
        hidden
        disabled={disabled}
      />

      {!selectedFile ? (
        <button
          type="button"
          className={`file-drop-zone ${
            isDragging ? "dragging" : ""
          }`}
          onClick={openFilePicker}
          onDragOver={(event) => {
            event.preventDefault();

            if (!disabled) {
              setIsDragging(true);
            }
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          disabled={disabled}
        >
          <div className="upload-main-icon">
            <FileUp size={29} />
          </div>

          <strong>Upload Email Evidence</strong>

          <span>
            Drag & drop your .eml file here or click to browse
          </span>

          <small>
            Supported format: EML • Maximum size: 10 MB
          </small>
        </button>
      ) : (
        <div className="selected-file-card">
          <div className="selected-file-left">
            <div className="selected-file-icon">
              <Mail size={21} />
            </div>

            <div className="selected-file-info">
              <strong>{selectedFile.name}</strong>

              <span>
                {selectedFile.size > 0
                  ? `${(selectedFile.size / 1024).toFixed(1)} KB`
                  : "0 KB"}
              </span>
            </div>
          </div>

          <div className="selected-file-right">
            <div className="file-valid">
              <ShieldCheck size={15} />
              Ready
            </div>

            <button
              type="button"
              className="remove-file-button"
              onClick={removeFile}
              disabled={disabled}
              aria-label="Remove selected file"
            >
              <X size={16} />
            </button>
          </div>
        </div>
      )}

      <div className="upload-security-note">
        <AlertCircle size={14} />
        <span>
          Email evidence is analyzed locally through the MailTrace AI
          forensic backend.
        </span>
      </div>
    </div>
  );
}

export default FileUpload;