# Evaluation

CheckUp is evaluated with two small FastAPI projects that implement comparable routes.
The vulnerable version contains deliberate security mistakes; the corrected version
uses safer alternatives.

The automated evaluation checks that the vulnerable project produces findings for:

1. Hardcoded credentials.
2. Shell command injection.
3. Dynamic Python execution.
4. SQL injection.
5. Request-controlled file access.
6. Unsafe Pickle deserialization.
7. Disabled TLS verification.

The corrected project must produce none of those findings. Both projects must still
produce six FastAPI route records and two pinned dependency records. OSV is replaced
with a deterministic local result during this evaluation so internet availability
cannot change the outcome.

This dataset demonstrates expected behaviour for supported patterns. It does not
measure performance on every possible Python application, so the results should not
be interpreted as a universal accuracy claim.

