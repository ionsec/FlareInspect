==========

Module Map

==========




Reference for the FlareInspect source tree.



Directory Structure


----


.. code-block::


    flareinspect/

    ├── src/

    │   ├── cli/

    │   │   ├── index.js          # CLI entry point (commander)

    │   │   ├── interactive.js    # Interactive REPL mode

    │   │   ├── welcome.js        # Docker welcome message

    │   │   ├── commands/

    │   │   │   ├── assess.js     # Assess command handler

    │   │   │   ├── export.js     # Export command handler

    │   │   │   ├── diff.js       # Diff command handler

    │   │   │   └── help.js       # Help command handler

    │   │   └── utils/

    │   │       └── banner.js     # ASCII art and banners

    │   ├── core/

    │   │   ├── config.js         # ConfigManager (file + env + CLI merge)

    │   │   ├── services/

    │   │   │   ├── assessmentService.js   # Orchestration, zone assessment

    │   │   │   ├── cloudflareClient.js    # Cloudflare API wrapper

    │   │   │   ├── securityBaseline.js    # Check definitions + scoring

    │   │   │   ├── reportService.js       # Report model generation

    │   │   │   ├── complianceEngine.js    # Framework control mapping

    │   │   │   ├── contextualScoring.js   # CVSS-style contextual scoring

    │   │   │   └── diffService.js         # Assessment comparison

    │   │   └── utils/

    │   │       ├── logger.js     # Winston logger (file + console)

    │   │       └── ocsf.js       # OCSF schema utilities

    │   ├── exporters/

    │   │   ├── json.js           # JSON + OCSF export

    │   │   ├── html.js           # Handlebars HTML report

    │   │   ├── sarif.js          # SARIF v2.1.0

    │   │   ├── markdown.js       # Markdown report

    │   │   ├── csv.js            # CSV with evidence columns

    │   │   └── asff.js           # AWS Security Finding Format

    │   └── plugins/

    │       └── interface.js       # Plugin base class + loader

    ├── templates/

    │   └── report.html           # Handlebars HTML report template

    ├── web/

    │   ├── server.js             # Express web server

    │   ├── data/assessments/      # Assessment storage

    │   └── public/

    │       ├── app.js            # Frontend JavaScript

    │       ├── styles.css        # Frontend styles

    │       └── *.png/svg         # Logo assets

    ├── tests/

    │   ├── assessmentService.test.js

    │   ├── complianceEngine.test.js

    │   ├── config.test.js

    │   ├── contextualScoring.test.js

    │   ├── diffService.test.js

    │   ├── exporters.test.js

    │   ├── plugins.test.js

    │   ├── webServerRoutes.test.js

    │   └── mocks/

    │       └── cloudflareResponses.js

    ├── Dockerfile

    ├── docker-compose.yml

    ├── render.yaml

    └── package.json




Key Module Sizes


----


  ========================  =======

   Module                    Lines

  ========================  =======

   ``assessmentService.js``    2825

   ``cloudflareClient.js``     1833

   ``securityBaseline.js``     924

   ``reportService.js``        682

   ``web/server.js``           595

  ========================  =======
