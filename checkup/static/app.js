const form = document.querySelector("#scan-form");
const pathInput = document.querySelector("#project-path");
const submitButton = form.querySelector("button");
const formError = document.querySelector("#form-error");
const results = document.querySelector("#results");
const findingList = document.querySelector("#finding-list");
const errorPanel = document.querySelector("#scan-errors");
const errorList = document.querySelector("#error-list");
const routeMap = document.querySelector("#route-map");
const routeList = document.querySelector("#route-list");
const dependencyReport = document.querySelector("#dependency-report");
const dependencyStatus = document.querySelector("#dependency-status");
const dependencyAlerts = document.querySelector("#dependency-alerts");
const severityFilter = document.querySelector("#severity-filter");
const exportButton = document.querySelector("#export-report");
const severityRanks = { low: 1, medium: 2, high: 3, critical: 4 };
let currentFindings = [];
let currentReport = null;

severityFilter.addEventListener("change", renderFilteredFindings);
exportButton.addEventListener("click", downloadReport);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setLoading(true);
  formError.hidden = true;
  results.hidden = true;

  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project_path: pathInput.value.trim() }),
    });
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "The scan could not be completed.");
    }

    renderReport(data);
  } catch (error) {
    formError.textContent = error.message || "CheckUp could not reach the local server.";
    formError.hidden = false;
  } finally {
    setLoading(false);
  }
});

function setLoading(isLoading) {
  submitButton.disabled = isLoading;
  submitButton.textContent = isLoading ? "Checking project…" : "Run check-up";
}

function renderReport(report) {
  currentReport = report;
  exportButton.hidden = false;
  document.querySelector("#results-title").textContent = `${report.project_name} report`;
  document.querySelector("#finding-count").textContent = report.findings.length;
  document.querySelector("#file-count").textContent = report.files_analyzed;
  document.querySelector("#route-count").textContent = report.routes.length;
  document.querySelector("#dependency-alert-count").textContent =
    report.dependency_vulnerabilities.length;
  findingList.replaceChildren();
  errorList.replaceChildren();
  routeList.replaceChildren();
  dependencyAlerts.replaceChildren();

  currentFindings = report.findings;
  severityFilter.value = "all";
  renderFilteredFindings();

  report.errors.forEach((error) => {
    const item = document.createElement("li");
    item.textContent = `${error.path}: ${error.message}`;
    errorList.append(item);
  });
  report.routes.forEach((route) => routeList.append(createRoute(route)));
  routeMap.hidden = report.routes.length === 0;
  renderDependencyReport(report);
  errorPanel.hidden = report.errors.length === 0;
  results.hidden = false;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function downloadReport() {
  if (!currentReport) {
    return;
  }

  const safeName = currentReport.project_name.replace(/[^a-z0-9_-]+/gi, "-");
  const reportFile = new Blob(
    [JSON.stringify(currentReport, null, 2)],
    { type: "application/json" },
  );
  const downloadUrl = URL.createObjectURL(reportFile);
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.download = `${safeName || "checkup"}-security-report.json`;
  link.click();
  URL.revokeObjectURL(downloadUrl);
}

function renderDependencyReport(report) {
  dependencyReport.hidden = report.dependencies.length === 0;
  if (report.dependencies.length === 0) {
    return;
  }

  if (!report.dependency_check_performed) {
    dependencyStatus.textContent =
      `${report.dependencies.length} pinned dependencies found. The vulnerability database was unavailable.`;
  } else if (report.dependency_vulnerabilities.length === 0) {
    dependencyStatus.textContent =
      `${report.dependencies.length} pinned dependencies checked. No known vulnerabilities were returned.`;
  } else {
    dependencyStatus.textContent =
      `${report.dependencies.length} pinned dependencies checked against OSV.`;
  }

  report.dependency_vulnerabilities.forEach((vulnerability) => {
    const article = document.createElement("article");
    article.className = "dependency-alert";
    const details = document.createElement("div");
    const packageName = document.createElement("strong");
    packageName.textContent = `${vulnerability.package} ${vulnerability.version}`;
    const advisory = document.createElement("span");
    advisory.textContent = `${vulnerability.advisory_id} · ${vulnerability.location.path}:${vulnerability.location.line}`;
    details.append(packageName, advisory);

    const link = document.createElement("a");
    link.href = vulnerability.advisory_url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = "View advisory";
    article.append(details, link);
    dependencyAlerts.append(article);
  });
}

function renderFilteredFindings() {
  const minimum = severityFilter.value;
  const visibleFindings = minimum === "all"
    ? currentFindings
    : currentFindings.filter(
      (finding) => severityRanks[finding.severity] >= severityRanks[minimum],
    );
  findingList.replaceChildren();

  if (visibleFindings.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-result";
    empty.textContent = currentFindings.length === 0
      ? "No findings were detected by the checks currently available."
      : "No findings match this severity filter.";
    findingList.append(empty);
  } else {
    visibleFindings.forEach((finding) => findingList.append(createFinding(finding)));
  }
}

function createRoute(route) {
  const article = document.createElement("article");
  article.className = "route";

  const method = document.createElement("span");
  method.className = "route-method";
  method.textContent = route.method;

  const path = document.createElement("span");
  path.className = "route-path";
  path.textContent = route.path;

  const detail = document.createElement("div");
  detail.className = "route-detail";
  const source = document.createElement("div");
  source.textContent = `${route.handler} · ${route.location.path}:${route.location.line}`;
  const security = document.createElement("div");
  security.className = "route-security";
  if (route.security_dependencies.length > 0) {
    security.textContent = `Visible security: ${route.security_dependencies.join(", ")}`;
  } else {
    security.classList.add("review");
    security.textContent = "Review access control: no route-level security dependency found";
  }
  detail.append(source, security);

  article.append(method, path, detail);
  return article;
}

function createFinding(finding) {
  const article = document.createElement("article");
  article.className = `finding severity-${finding.severity}`;

  const topline = document.createElement("div");
  topline.className = "finding-topline";
  const title = document.createElement("h3");
  title.textContent = finding.title;
  const severity = document.createElement("span");
  severity.className = `severity ${finding.severity}`;
  severity.textContent = finding.severity;
  const confidence = document.createElement("span");
  confidence.className = "confidence";
  confidence.textContent = `${finding.confidence} confidence`;
  const labels = document.createElement("div");
  labels.append(severity, confidence);
  topline.append(title, labels);

  const location = document.createElement("p");
  location.className = "location";
  location.textContent = `${finding.location.path}:${finding.location.line}`;
  if (finding.git_status) {
    location.textContent += ` · Git: ${finding.git_status}`;
  }

  const description = document.createElement("p");
  description.className = "finding-description";
  description.textContent = finding.description;

  const evidence = document.createElement("pre");
  evidence.className = "evidence";
  evidence.textContent = finding.evidence;

  const remediation = document.createElement("p");
  remediation.className = "remediation";
  remediation.textContent = `Suggested fix: ${finding.remediation}`;

  article.append(topline, location, description, evidence, remediation);
  return article;
}
