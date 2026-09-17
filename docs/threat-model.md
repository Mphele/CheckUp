# CheckUp threat model

## Assets

CheckUp must protect the developer's local files, credentials, source code, scan
results, and computer from a project selected for analysis.

## Trust boundaries

The selected project is untrusted input. Filenames, source lines, route paths, and
dependency names must be treated as attacker-controlled. OSV is an external service;
its availability is not guaranteed. The dashboard is local, but repository content
still cannot be trusted as HTML.

## Main threats and controls

| Threat | Control |
| --- | --- |
| Submitted code executes during analysis | CheckUp reads text and parses syntax trees; it never imports or runs the project. |
| Dependencies execute installation scripts | CheckUp reads requirement declarations and never installs submitted dependencies. |
| A symbolic link escapes the selected folder | File discovery does not follow symbolic-link files or directories. |
| Large files exhaust memory or delay a scan | Individual files are limited to 1 MB and generated directories are excluded. |
| A secret appears in a report | Suspected credential values are replaced with `<redacted>`. |
| Repository text injects scripts into the UI | Dynamic values are inserted with `textContent`, not interpreted as HTML. |
| OSV is offline or malformed | Local analysis completes and the failed dependency check is shown as a scan error. |
| A scan claims coverage it did not achieve | Reports separate discovered files, analysed files, findings, and errors. |

## Accepted limitations

The local API accepts a filesystem path supplied by the person running CheckUp. This
is intentional because the application is designed for a single developer on
localhost. CheckUp should not be exposed as a shared network service without adding
authentication, access controls, stronger isolation, and stricter path restrictions.

