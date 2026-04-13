==============
assess Command
==============
==============

Run a comprehensive Cloudflare security assessment against your account and zones.

Usage
-----

.. code-block:: bash

   flareinspect assess [options]

Options
-------

============================  ====================================================================================  ===============================
Option                        Description                                                                           Default                        
============================  ====================================================================================  ===============================
``-t, --token <token>``       Cloudflare API token *(required)*                                                     —                              
``-o, --output <file>``       Output file path for assessment results                                               Auto-generated timestamped file
``-f, --format <format>``     Output format: ``json``, ``html``, ``sarif``, ``markdown``, ``csv``, ``ocsf``         ``json``                       
``--no-export``               Skip automatic export of results                                                      —                              
``--ci``                      CI/CD mode: JSON to stdout, no spinners, exit codes by threshold                      —                              
``--threshold <score>``       Minimum security score (0–100) to pass in CI mode                                     —                              
``--fail-on <severity>``      Fail if any finding at or above severity: ``critical``, ``high``, ``medium``, ``low`  `         —                    
``--zones <zones>``           Comma-separated list of zone names to assess                                          All zones                      
``--exclude-zones <zones>``   Comma-separated list of zone names to exclude                                         —                              
``--checks <checks>``         Comma-separated list of check categories to run                                       All categories                 
``--concurrency <n>``         Number of zones to assess in parallel                                                 ``3``                          
``--compliance <framework>``  Generate compliance report: ``cis``, ``soc2``, ``pci``, ``nist``                      —                              
``--sensitivity <level>``     Data sensitivity level for contextual scoring: ``critical``, ``high``, ``medium``, `  `low``    —                    
``--debug``                   Enable debug logging                                                                  —                              
============================  ====================================================================================  ===============================

Check Categories
-----------------

The following 21 check categories can be targeted with ``--checks``:

====================  ===========================================
Category              Description                                
====================  ===========================================
``account``           Account-level settings and configuration   
``dns``               DNS record security and resolution         
``ssl``               SSL/TLS certificate and configuration      
``waf``               Web Application Firewall rules and policies
``zerotrust``         Zero Trust network access configuration    
``workers``           Cloudflare Workers security settings       
``pages``             Cloudflare Pages deployment security       
``api``               API gateway and shielding configuration    
``bot``               Bot management and mitigation              
``logpush``           Log push destination and coverage          
``mtls``              Mutual TLS authentication settings         
``securitytxt``       Security.txt presence and validity         
``attack-surface``    Attack surface reduction rules             
``dlp``               Data Loss Prevention policies              
``tunnels``           Cloudflare Tunnels configuration           
``gateway``           Secure Web Gateway policies                
``page-shield``       Page Shield script monitoring              
``cache``             Cache security and configuration           
``snippets``          Cache and transform snippets               
``custom-hostnames``  Custom hostname security                   
``ai-gateway``        AI Gateway security configuration          
====================  ===========================================

CI Mode
--------

CI mode is designed for automated pipelines. It:

- Outputs the full assessment JSON to **stdout** (no spinners or banners)
- Suppresses all interactive terminal output
- Sets the process exit code based on ``--threshold`` and ``--fail-on``

Exit Code Logic
^^^^^^^^^^^^^^^

======================================================  =========
Condition                                               Exit Code
======================================================  =========
Assessment passes threshold and severity gate           ``0``    
Overall score < ``--threshold`` value                   ``1``    
Any finding at or above ``--fail-on`` severity is FAIL  ``1``    
Assessment itself fails (invalid token, API error)      ``1``    
======================================================  =========

Examples
--------

.. rubric:: Basic Assessment

.. code-block:: bash

   flareinspect assess --token $CLOUDFLARE_TOKEN

.. rubric:: Targeted Assessment

.. code-block:: bash

   flareinspect assess --token $CLOUDFLARE_TOKEN --zones example.com --checks dns,ssl,waf

.. rubric:: CI/CD with Gating

.. code-block:: bash

   flareinspect assess --token $CLOUDFLARE_TOKEN --ci --threshold 80 --fail-on high

.. rubric:: With Compliance Report

.. code-block:: bash

   flareinspect assess --token $CLOUDFLARE_TOKEN --compliance cis --sensitivity high
