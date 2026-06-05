# FlareInspect — Splunk integration

A minimal Splunk Technology Add-on (TA-flareinspect) + dashboard + saved searches,
paired with the FlareInspect shipper that pushes findings via HEC.

## Layout

```
integrations/splunk/
├── README.md
└── TA-flareinspect/
    ├── default/
    │   ├── app.conf
    │   ├── props.conf            # field extractions for sourcetype
    │   ├── transforms.conf       # field renames
    │   ├── savedsearches.conf    # 2 saved searches
    │   └── data/ui/views/flareinspect_overview.xml
```

## 1. Install the TA

Copy `TA-flareinspect/` to `$SPLUNK_HOME/etc/apps/TA-flareinspect/`, or
package it (`splunk package app TA-flareinspect`) and install via the
Splunk UI / deployer.

## 2. Configure the HEC token + index

- Splunk → Settings → Data → HTTP Event Collector → New Token
  - Index: `main` (or the index you'll use)
  - Source type override: `cloudflare:flareinspect:finding` (this is
    what FlareInspect ships; the TA's `props.conf` is keyed on it)
- Copy the token to `FLAREINSPECT_SPLUNK_HEC_TOKEN`

## 3. Ship findings

```bash
flareinspect ship -i assessment.json \
  --target splunk \
  --hec-url https://splunk.example.com:8088 \
  --hec-token $FLAREINSPECT_SPLUNK_HEC_TOKEN
```

Or the web API:
```bash
curl -X POST http://localhost:3000/api/integrations/ship \
  -H 'Content-Type: application/json' \
  -d '{ "target": "splunk", "hecUrl": "https://splunk.example.com:8088", "hecToken": "..." }'
```

Or the file exporter (replay with curl):
```bash
flareinspect ship -i assessment.json --target file --out-dir ./out/
curl -k https://splunk.example.com:8088/services/collector/event \
  -H "Authorization: Splunk $HEC_TOKEN" \
  --data-binary @./out/flareinspect-hec-*.ndjson
```

## What you get

- **Sourcetype** `cloudflare:flareinspect:finding` with `KV_MODE = json` so the
  inner event auto-extracts without manual field rules.
- **Field aliases** (in `props.conf`) — `vulnerability.severity` is
  the CIM-aligned field for severity; this is what the Vulnerabilities
  dashboard expects.
- **Saved searches** under the `flarestinspect-` prefix for the operator
  to enable alerts on.
- **Dashboard** `FlareInspect overview` — severity bar, top attack
  paths (pie), recent findings table.

## Test data

```bash
flareinspect ship -i tests/fixtures/assessment-bad.json \
  --target splunk \
  --hec-url https://splunk.example.com:8088 \
  --hec-token $HEC_TOKEN
```
