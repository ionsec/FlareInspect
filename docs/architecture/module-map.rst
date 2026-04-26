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
   │       └── help.js         Help command implementation
   ├── core/
   │   ├── config.js           Configuration file loader and merger
   │   ├── services/
   │   │   ├── assessmentService.js   Assessment orchestration
   │   │   ├── cloudflareClient.js    Cloudflare SDK + REST wrapper
   │   │   ├── complianceEngine.js    Framework mapping engine
   │   │   ├── contextualScoring.js   CVSS-inspired scoring
   │   │   ├── diffService.js         Drift detection engine
   │   │   ├── reportService.js       Report model and summary
   │   │   └── securityBaseline.js     Check definitions and weights
   │   └── utils/
   │       ├── logger.js        Winston logger configuration
   │       └── ocsf.js          OCSF normalization utilities
   ├── exporters/
   │   ├── asff.js             AWS Security Finding Format
   │   ├── csv.js              CSV tabular export
   │   ├── html.js             HTML interactive report
   │   ├── json.js             JSON full results
   │   ├── markdown.js         Markdown text report
   │   └── sarif.js            SARIF for GitHub Advanced Security
   └── plugins/
       └── interface.js        Plugin loader and API

Key Module Sizes
-----------------

========================  =====
Module                    Lines
========================  =====
``assessmentService.js``  2825 
``cloudflareClient.js``   1843 
``securityBaseline.js``   924  
``reportService.js``      682  
``web/server.js``         595  
========================  =====
