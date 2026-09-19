# CheckUp

CheckUp is a local security review assistant for student Python developers. It scans
source code and configuration without importing the submitted application, running
its code, or installing its dependencies.

The first release focuses on FastAPI projects. It combines general Python security
checks with framework-aware route mapping and direct request-input tracing.

## Current checks

- Hardcoded credentials and private keys, with redacted values and current Git status.
- Shell execution through `os.system` and `subprocess` with `shell=True`.
- Dynamic Python execution through `eval` and `exec`.
- Disabled TLS certificate verification.
- Unsafe Pickle deserialization.
- Dynamically constructed SQL queries.
- FastAPI request data flowing into shell, dynamic-code, SQL, and file operations.
- FastAPI route dependencies that appear to provide authentication or authorisation.
- Known vulnerabilities in pinned `requirements*.txt` dependencies using OSV.

## Requirements

- Python 3.11 or newer.
- Internet access when checking dependency vulnerabilities. Local source checks still
  work if OSV is unavailable.

## Setup

From the project folder on Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Python 3.11 or 3.12 can be used in place of 3.13.

For editable development installs, `python -m pip install -e ".[dev]"` remains
available through `pyproject.toml`.

## Run CheckUp

```powershell
python -m checkup
```

Open `http://127.0.0.1:8000`, enter the full path to a local project, and select
**Run check-up**. Scan reports can be downloaded as JSON.

Use `python -m checkup --reload` while developing CheckUp itself, or `--port 8123`
to select a different local port. Installing the project also provides the equivalent
`checkup` command.

For a demonstration, scan `examples/vulnerable_api`. It contains deliberate security
mistakes and must never be deployed.

## Run the tests

```powershell
python -m pytest
```

The test suite uses temporary project directories and mocked OSV responses. It does
not execute the vulnerable demonstration application.

## Project structure

- `checkup/main.py` defines the local FastAPI server and scan endpoint.
- `checkup/models.py` defines the validated report data.
- `checkup/scanning/` contains file discovery, security rules, route analysis, the
  scan engine, dependency parsing, and OSV integration.
- `checkup/templates/` and `checkup/static/` contain the local dashboard.
- `examples/` contains vulnerable and corrected projects used for evaluation.
- `tests/` verifies individual rules and complete scan behaviour.
- `docs/` explains the threat model, rules, limitations, and evaluation.

## Scope and limitations

CheckUp is an educational static-analysis project, not a complete penetration test.
It can miss vulnerabilities that depend on runtime configuration or complex flows
between functions, and suspicious patterns can still require human review. A scan
with no findings does not prove that a project is secure.

See [the rule reference](docs/rules.md), [threat model](docs/threat-model.md), and
[evaluation](docs/evaluation.md) for the reasoning behind the project.

verification code: WTC-26YFWL5H
