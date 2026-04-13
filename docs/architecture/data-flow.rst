=========
Data Flow
=========
=========

Assessment Flow
----------------

1. CLI parses command flags and config file
2. CloudflareClient authenticates with the provided token
3. AssessmentService enumerates accounts and zones
4. For each zone, SecurityBaseline checks are evaluated against live API data
5. Results are collected into a report object by ReportService
6. ComplianceEngine maps findings to framework controls
7. ContextualScoring adjusts severity based on zone metadata
8. Exporters transform the report object into the requested format
9. Results are written to disk and/or stdout

Drift Flow
----------

1. DiffService loads baseline and current assessment JSON files
2. Findings are matched by check ID and zone
3. Each matched pair is classified as REGRESSION, IMPROVEMENT, NEW, RESOLVED, or UNCHANGED
4. Drift score is calculated from severity-weighted improvement and regression totals
5. Results are formatted and returned with an appropriate exit code

Web Dashboard Flow
-------------------

1. Express server receives HTTP request
2. Authentication middleware checks X-API-Key (if configured)
3. Route handler validates input parameters
4. AssessmentService or DiffService is invoked with the validated parameters
5. Response is serialized as JSON or the requested export format
6. Static files are served from ``web/public/``
