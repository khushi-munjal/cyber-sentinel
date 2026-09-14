// ─────────────────────────────────────────────────────────────────────────────
// MailTrace AI  ·  Centralized API Service
// Backend: FastAPI running on http://127.0.0.1:8001
// ─────────────────────────────────────────────────────────────────────────────

export const API_BASE_URL = "http://127.0.0.1:8001";

const DEFAULT_TIMEOUT = 60000; // 60 s — analysis can take a while

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    return response;
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("Request timed out. The backend may be unavailable.");
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function parseResponse(response) {
  let data = {};
  try {
    data = await response.json();
  } catch {
    // non-JSON response — keep empty object
  }

  if (!response.ok) {
    const message =
      data?.detail ||
      data?.message ||
      `Server returned ${response.status} ${response.statusText}`;
    throw new Error(message);
  }

  return data;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * GET /health
 * Returns { status, timestamp }
 */
export async function checkHealth() {
  const response = await fetchWithTimeout(`${API_BASE_URL}/health`, {}, 8000);
  return parseResponse(response);
}

/**
 * POST /analyze
 * Accepts a multipart .eml file upload.
 * Returns the full analysis result object.
 */
export async function analyzeEmail(file) {
  if (!file) throw new Error("No file provided.");

  const ext = file.name.toLowerCase().split(".").pop();
  if (ext !== "eml") throw new Error("Only .eml email files are supported.");

  const formData = new FormData();
  formData.append("file", file);

  const response = await fetchWithTimeout(
    `${API_BASE_URL}/analyze`,
    { method: "POST", body: formData },
    120000 // 2-minute timeout for analysis
  );

  return parseResponse(response);
}

/**
 * GET /cases
 * Returns { total_cases, cases: [{case_id, filename, sender, receiver, subject, risk_score, risk_level}] }
 */
export async function getCases() {
  const response = await fetchWithTimeout(`${API_BASE_URL}/cases`);
  return parseResponse(response);
}

/**
 * GET /cases/:caseId
 * Returns the full cached analysis result for a case.
 */
export async function getCase(caseId) {
  if (!caseId) throw new Error("Case ID is required.");
  const response = await fetchWithTimeout(
    `${API_BASE_URL}/cases/${encodeURIComponent(caseId)}`
  );
  return parseResponse(response);
}

/**
 * GET /analytics
 * Returns { total_cases, risk_distribution: {critical,high,medium,low}, engine: {...} }
 */
export async function getAnalytics() {
  const response = await fetchWithTimeout(`${API_BASE_URL}/analytics`);
  return parseResponse(response);
}

/**
 * GET /threat-graph/:caseId
 * Returns the threat graph object for a specific case.
 */
export async function getThreatGraph(caseId) {
  if (!caseId) throw new Error("Case ID is required.");
  const response = await fetchWithTimeout(
    `${API_BASE_URL}/threat-graph/${encodeURIComponent(caseId)}`
  );
  return parseResponse(response);
}

/**
 * GET /geo/:caseId
 * Returns the geo intelligence object for a specific case.
 */
export async function getGeoIntelligence(caseId) {
  if (!caseId) throw new Error("Case ID is required.");
  const response = await fetchWithTimeout(
    `${API_BASE_URL}/geo/${encodeURIComponent(caseId)}`
  );
  return parseResponse(response);
}

/**
 * Returns the URL for downloading a forensic PDF report.
 * GET /reports/:caseId  → FileResponse (PDF)
 */
export function getReportUrl(caseId) {
  if (!caseId) return null;
  return `${API_BASE_URL}/reports/${encodeURIComponent(caseId)}`;
}

/**
 * Opens the forensic PDF report in a new tab.
 */
export function openForensicReport(caseId) {
  const url = getReportUrl(caseId);
  if (url) window.open(url, "_blank", "noopener,noreferrer");
}
