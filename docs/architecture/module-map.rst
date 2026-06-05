==========
Module Map
==========

Project Structure
------------------

.. code-block:: text

   src/
   ├── cli/
   │   ├── index.js            CLI entry point and command router
   │   ├── interactive.js      Interactive REPL mode
   │   ├── welcome.js          Welcome screen and banner
   │   ├── utils/
   │   │   └── banner.js       ASCII art and version banner
   │   └── commands/
   │       ├── assess.js       Assess command implementation
   │       ├── diff.js         Diff command implementation
   │       ├── export.js       Export command implementation
   │       ├── help.js         Help command implementation
   │       ├── notify.js       Notify command (v2.0)
   │       ├── remediate.js    Remediate command
   │       └── ship.js         Ship command (v2.0)
   ├── core/
   │   ├── config.js           Configuration file loader and merger
   │   ├── graph/              Resource graph + attack-path engine (v2.0)
   │   │   ├── resourceGraph.js  Typed nodes (14) + edges (8)
   │   │   ├── attackPaths.js    5 rule-based detectors
   │   │   └── severity.js       SEVERITY_ORDER / worst / worstOf
   │   ├── auth/               Edit-scope policy (v2.0)
   │   │   └── editScope.js    verifyEditScope / isRemediationEnabled
   │   ├── integrations/       External-system integrations (v2.0)
   │   │   ├── notify/         Slack / Teams / webhook dispatchers
   │   │   └── siem/           Elasticsearch / Splunk shippers
   │   ├── services/
   │   │   ├── assessmentService.js   Assessment orchestration
   │   │   ├── cloudflareClient.js    Cloudflare SDK + REST wrapper
   │   │   ├── complianceEngine.js    Framework mapping engine
   │   │   ├── contextualScoring.js   CVSS-inspired scoring
   │   │   ├── diffService.js         Drift detection engine
   │   │   ├── reportService.js       Report model and summary
   │   │   └── securityBaseline.js     Check definitions and weights
   │   ├── remediation/        Apply/rollback engine + backup manager
   │   │   ├── remediationEngine.js
   │   │   └── backupManager.js
   │   └── utils/
   │       ├── logger.js        Winston logger configuration
   │       └── ocsf.js          OCSF normalization utilities
   ├── exporters/
   │   ├── asff.js             AWS Security Finding Format
   │   ├── csv.js              CSV tabular export
   │   ├── ecs.js              ECS NDJSON (v2.0; same shape as the live ES shipper)
   │   ├── html.js             HTML interactive report
   │   ├── json.js             JSON full results
   │   ├── markdown.js         Markdown text report
   │   ├── sarif.js            SARIF for GitHub Advanced Security
   │   └── splunkHec.js        Splunk HEC NDJSON (v2.0)
   └── plugins/
       └── interface.js        Plugin loader and API

   mcp/                        MCP server (v2.0)
   ├── server.mjs              Stdio transport, six tools
   └── bridge.cjs              CJS facade for Jest tests

   integrations/               Packaged SIEM apps (v2.0)
   ├── elastic/
   │   ├── README.md
   │   ├── flareinspect-dashboard.ndjson
   │   └── flareinspect-index-template.json
   └── splunk/
       ├── README.md
       └── TA-flareinspect/
           ├── default/
           │   ├── app.conf
           │   ├── props.conf
           │   ├── transforms.conf
           │   ├── savedsearches.conf
           │   └── data/ui/views/flareinspect_overview.xml

   web/
   ├── server.js               Express + new v2.0 endpoints
   │                           (posture/graph, notify,
   │                            integrations/ship, template/elastic)
   └── public/
       ├── app.js              Dashboard SPA
       ├── index.html
       ├── styles.css
       ├── postureMap.js       Posture map SVG engine (v2.0)
       ├── postureMap.css      Posture map styling (v2.0)
       ├── flare-inspect-logo.svg
       └── flare-inspect-glyph.svg

   tests/                      Jest suite (262 tests, all green)

Key Module Sizes
-----------------

========================  =====
Module                    Lines
========================  =====
``assessmentService.js``  2825
``cloudflareClient.js``   1843
``securityBaseline.js``   924
``reportService.js``      682
``web/server.js``         ~700
========================  =====
