# Security rule reference

CheckUp separates severity from confidence. Severity estimates the possible impact;
confidence describes how directly the source code supports the conclusion.

| Rule | What it detects | Default severity | Default confidence |
| --- | --- | --- | --- |
| `secrets.hardcoded-credential` | A literal assigned to a security-sensitive name | High | Medium |
| `secrets.private-key` | A private-key header inside a scanned file | Critical | High |
| `secrets.private-key-placeholder` | A short or explicitly labelled example key block | Low | High |
| `python.shell-injection` | A shell-enabled subprocess or `os.system` call | High | Medium |
| `python.dynamic-code-execution` | `eval` or `exec` | High | Medium |
| `python.disabled-tls-verification` | Supported HTTP calls with `verify=False` | Medium | High |
| `python.unsafe-pickle` | `pickle.load` or `pickle.loads` | High | Medium |
| `python.dynamic-sql-query` | Formatted SQL passed to `execute` or `executemany` | High | Medium |
| `fastapi.request-to-shell` | A route input reaching a shell command | High | High |
| `fastapi.request-to-dynamic-code` | A route input reaching `eval` or `exec` | High | High |
| `fastapi.request-to-sql-query` | A route input reaching a database query | High | High |
| `fastapi.request-to-file-path` | A route input reaching a supported file operation | High | High |

FastAPI route mapping is informational rather than a vulnerability rule. CheckUp lists
route methods, paths, handlers, inputs, dependencies, and likely security dependencies.
A route without a visible security dependency is marked for review, not declared
vulnerable, because middleware or router-level protection may exist elsewhere.

Dependency advisories come from OSV and require an exact version from a pinned
`requirements*.txt` entry. Unpinned requirements are not queried.

## Known limitations

- Request-flow analysis currently stays inside a route handler and follows local
  assignments. It does not trace values through arbitrary helper functions.
- Imported aliases such as `import subprocess as sp` are not resolved.
- Secret detection uses patterns and variable names, so unfamiliar credential formats
  may be missed.
- Git status is reported for secret findings when the project belongs to a local Git
  repository. It describes the current checkout and does not prove that a secret was
  never present under another filename or on a remote branch.
- Route security classification partly relies on dependency names.
- Dependency analysis currently supports pinned requirements text files only.
- Runtime behaviour, infrastructure, middleware configuration, and deployed network
  exposure are outside the current scan.
