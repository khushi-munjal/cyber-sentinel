const API_BASE_URL = "https://cyber-sentinel-nkti.onrender.com";

async function parseResponse(response) {
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data?.detail ||
        data?.message ||
        `Request failed with status ${response.status}`
    );
  }

  return data;
}

export async function checkHealth() {
  const response = await fetch(
    `${API_BASE_URL}/health`
  );

  return parseResponse(response);
}

export async function analyzeEmail(file) {
  if (!file) {
    throw new Error("Please select an email file.");
  }

  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(
    `${API_BASE_URL}/analyze`,
    {
      method: "POST",
      body: formData,
    }
  );

  return parseResponse(response);
}

export async function getCases() {
  const response = await fetch(
    `${API_BASE_URL}/cases`
  );

  return parseResponse(response);
}

export async function getCase(caseId) {
  if (!caseId) {
    throw new Error("Case ID is required.");
  }

  const response = await fetch(
    `${API_BASE_URL}/cases/${encodeURIComponent(caseId)}`
  );

  return parseResponse(response);
}

export async function getThreatGraph(caseId) {
  if (!caseId) {
    throw new Error("Case ID is required.");
  }

  const response = await fetch(
    `${API_BASE_URL}/threat-graph/${encodeURIComponent(
      caseId
    )}`
  );

  return parseResponse(response);
}

export async function getGeoIntelligence(caseId) {
  if (!caseId) {
    throw new Error("Case ID is required.");
  }

  const response = await fetch(
    `${API_BASE_URL}/geo/${encodeURIComponent(caseId)}`
  );

  return parseResponse(response);
}

export async function getAnalytics() {
  const response = await fetch(
    `${API_BASE_URL}/analytics`
  );

  return parseResponse(response);
}

export function getReportUrl(caseId) {
  if (!caseId) {
    return null;
  }

  return `${API_BASE_URL}/reports/${encodeURIComponent(
    caseId
  )}`;
}

export function openForensicReport(caseId) {
  const url = getReportUrl(caseId);

  if (!url) {
    return;
  }

  window.open(url, "_blank", "noopener,noreferrer");
}

export { API_BASE_URL };