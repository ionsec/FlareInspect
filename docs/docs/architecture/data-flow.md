# Data Flow

Step-by-step walkthrough of a FlareInspect assessment.

## Assessment Flow

```
1. CLI parses command → ConfigManager merges options
2. CloudflareClient connects with API token
3. testConnection() verifies token and retrieves account info
4. getZones() enumerates all visible zones
5. Filter zones by --zones / --exclude-zones
6. Account-level assessments:
   ├── Members & MFA status
   ├── Audit logs
   ├── Security Insights
   ├── Zero Trust config
   ├── Workers/Pages
   ├── Tunnels & Gateway
   └── AI Gateway
7. Zone-level assessments (parallel, p-limit):
   ├── DNS records
   ├── SSL/TLS settings
   ├── WAF rules
   ├── Firewall rules
   ├── Rate limits
   ├── Bot management
   ├── Page rules
   ├── mTLS
   ├── Logpush
   ├── Security.txt
   ├── DLP
   ├── Page Shield
   ├── Custom hostnames
   ├── Cache Deception Armor
   ├── Snippets
   ├── Configuration/Transform rules
   └── Origin certificates
8. SecurityBaseline evaluates each API response against check definitions
9. Findings aggregated with evidence (observed, expected, affected entities)
10. SecurityBaseline.calculateScore() produces weighted score and grade
11. Optional: ComplianceEngine maps findings to framework controls
12. Optional: ContextualScoring adjusts severity by zone plan and exposure
13. ReportService generates the report model (exec summary, analysis, recs)
14. Assessment JSON saved to file
15. Optional: Export to requested format
```

## Export Flow

```
1. Load assessment JSON from file
2. Validate assessment structure (assessmentId + findings)
3. Instantiate format-specific exporter
4. Exporter.transform(assessment) → format output
5. Write to output file
```

## Diff Flow

```
1. Load baseline and current assessment JSON files
2. Build finding maps keyed by checkId::resourceId
3. Classify each finding: NEW/RESOLVED/REGRESSION/IMPROVEMENT/UNCHANGED
4. Calculate score delta, grade delta, service-level deltas
5. Calculate drift score (-100 to +100)
6. Output or save diff results
```

## Web API Flow

```
1. Express server receives request
2. authenticateApiKey() checks X-API-Key (if configured)
3. Input validation (UUID, framework, concurrency, zones)
4. AssessmentService or DiffService processes request
5. Persist assessment to web/data/assessments/
6. Return JSON response
```
