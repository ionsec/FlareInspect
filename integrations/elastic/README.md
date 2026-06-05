# FlareInspect — Kibana integration

ECS-aligned index template + saved-objects NDJSON (data view, saved search, two Lens panels, dashboard).

## 1. Create the index template

```bash
curl -X PUT "$ES_URL/_index_template/flareinspect" \
  -H "Authorization: ApiKey $ES_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @flareinspect-index-template.json
```

The template auto-applies to any index matching `flareinspect-*`.

## 2. Import the saved objects (data view, panels, dashboard)

Kibana → Stack Management → Saved Objects → **Import** →
pick `flareinspect-dashboard.ndjson`.

Or via the API:

```bash
curl -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  --form file=@flareinspect-dashboard.ndjson
```

## 3. Ship findings

Either:
- The FlareInspect CLI: `flareinspect ship -i assessment.json --target elastic --es-url ... --es-api-key ...`
- The web API: `POST /api/integrations/ship` with `{ target: "elastic", esUrl, esApiKey, assessment }`
- The file exporter: `flareinspect ship -i assessment.json --target file --out-dir ./out/`

## What you get

- **Index template** with all ECS field types pre-configured (incl. nested
  `threat.enrichments`).
- **Data view** `flareinspect-*` with `@timestamp` as the time field.
- **Saved search** `FlareInspect findings` — query: `event.module : "flareinspect"`.
- **Lens panel** `FlareInspect — Severity` — terms aggregation on
  `vulnerability.severity`.
- **Lens panel** `FlareInspect — Attack paths` — terms aggregation on
  `flareinspect.attack_path_ids` (count of findings per attack path).
- **Dashboard** `FlareInspect overview` — combines all of the above.

## Test data

Ship a known-bad assessment to populate the dashboard:

```bash
flareinspect ship -i tests/fixtures/assessment-bad.json \
  --target elastic --es-url $ES_URL --es-api-key $ES_API_KEY
```

The exported file format is identical to what `flareinspect ship --target file` writes —
so a manual replay (`curl --data-binary @flareinspect-findings-*.ndjson $ES_URL/_bulk`)
produces the same documents.
