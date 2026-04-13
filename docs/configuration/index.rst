=============
Configuration
=============

.. toctree::
   :maxdepth: 1
   :hidden:

   config-file
   env-vars
   cli-override-precedence

Configuration Methods
----------------------

FlareInspect supports three configuration methods (in order of precedence):

1. **CLI flags** — highest priority, override everything
2. **Config file** — ``.flareinspect.yml``, ``.flareinspect.yaml``, or ``flareinspect.config.json``
3. **Environment variables** — ``CLOUDFLARE_TOKEN``, etc.

See the pages below for details.
