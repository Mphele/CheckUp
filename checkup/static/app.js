const form = document.querySelector("#scan-form");
const pathInput = document.querySelector("#project-path");
const submitButton = form.querySelector("button");
const formError = document.querySelector("#form-error");
const results = document.querySelector("#results");
const findingList = document.querySelector("#finding-list");
const errorPanel = document.querySelector("#scan-errors");
const errorList = document.querySelector("#error-list");

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
  document.querySelector("#results-title").textContent = `${report.project_name} report`;
  document.querySelector("#finding-count").textContent = report.findings.length;
  document.querySelector("#file-count").textContent = report.files_analyzed;
  findingList.replaceChildren();
  errorList.replaceChildren();

  if (report.findings.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-result";
    empty.textContent = "No findings were detected by the checks currently available.";
    findingList.append(empty);
  } else {
    report.findings.forEach((finding) => findingList.append(createFinding(finding)));
  }

  report.errors.forEach((error) => {
    const item = document.createElement("li");
    item.textContent = `${error.path}: ${error.message}`;
    errorList.append(item);
  });
  errorPanel.hidden = report.errors.length === 0;
  results.hidden = false;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function createFinding(finding) {
  const article = document.createElement("article");
  article.className = "finding";

  const topline = document.createElement("div");
  topline.className = "finding-topline";
  const title = document.createElement("h3");
  title.textContent = finding.title;
  const severity = document.createElement("span");
  severity.className = "severity";
  severity.textContent = finding.severity;
  topline.append(title, severity);

  const location = document.createElement("p");
  location.className = "location";
  location.textContent = `${finding.location.path}:${finding.location.line}`;

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
