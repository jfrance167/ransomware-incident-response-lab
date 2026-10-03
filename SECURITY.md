# Security Policy

Only the latest commit on the default branch is supported.

Report security concerns through GitHub private vulnerability reporting when available. Never submit malware, real credentials, private incident evidence, production hostnames, customer data, or live command-and-control indicators.

The sample telemetry is intentionally suspicious but inert. Vulnerabilities in parsing, report generation, workflow security, or boundaries that could cause telemetry content to execute remain in scope.

The JSONL reader caps input at 100 MiB, each line at 1 MiB, and the event count
at 100,000. Markdown report fields are escaped, control characters normalized,
and common URL schemes defanged; JSON output retains the parsed evidence values.
