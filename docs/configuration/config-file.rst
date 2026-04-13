==================
Configuration File
==================
==================

FlareInspect can read default settings from a configuration file, which is useful for teams that want consistent assessment parameters without repeating CLI flags.

Search Order
-------------

FlareInspect searches for a configuration file starting from the current working directory and walking upward to the filesystem root. The first file found wins:

1. ``.flareinspect.yml``
2. ``.flareinspect.yaml``
3. ``flareinspect.config.json``

YAML Schema
-----------

.. code-block:: yaml

   # FlareInspect configuration file
   token: YOUR_CLOUDFLARE_TOKEN

   output:
     format: json
     directory: ./output

   assessment:
     concurrency: 3
     checks:
       - dns
       - ssl
       - waf
     zones:
       - example.com
       - docs.example.com
     excludeZones:
       - staging.example.com

   compliance:
     framework: cis

   scoring:
     sensitivity: medium

   ci:
     threshold: 80
     failOn: high

JSON Schema
-----------

The equivalent ``flareinspect.config.json``:

.. code-block:: json

   {
     "token": "YOUR_CLOUDFLARE_TOKEN",
     "output": {
       "format": "json",
       "directory": "./output"
     },
     "assessment": {
       "concurrency": 3,
       "checks": ["dns", "ssl", "waf"],
       "zones": ["example.com", "docs.example.com"],
       "excludeZones": ["staging.example.com"]
     },
     "compliance": {
       "framework": "cis"
     },
     "scoring": {
       "sensitivity": "medium"
     },
     "ci": {
       "threshold": 80,
       "failOn": "high"
     }
   }

Environment Variable Interpolation
------------------------------------

Values in the config file that start with ``$`` are resolved from environment variables:

.. code-block:: yaml

   token: $CLOUDFLARE_TOKEN

When ``CLOUDFLARE_TOKEN`` is set in the environment, FlareInspect replaces ``$CLOUDFLARE_TOKEN`` with its value. This avoids hardcoding secrets in the config file.

Simple YAML Parser Notes
--------------------------

FlareInspect uses a built-in YAML parser that supports:

- Top-level and one-level-nested key-value pairs
- String, number, and boolean values
- Inline lists (array values)
- Comment lines starting with ``#``

It does **not** support advanced YAML features such as anchors, aliases, multi-line strings, or deeply nested objects. For complex configurations, use the JSON format instead.
