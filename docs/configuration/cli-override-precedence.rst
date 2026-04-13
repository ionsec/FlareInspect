===================
Override Precedence
===================
===================

When the same setting can come from multiple sources, FlareInspect resolves conflicts using a strict precedence order:

**CLI flag → Config file → Environment variable → Default**

The first source that provides a value wins. Sources later in the chain are ignored for that setting.

Precedence Order (highest to lowest)
-------------------------------------

===========  ====================  ==================================================
Priority     Source                Example                                           
===========  ====================  ==================================================
1 (highest)  CLI flag              ``--threshold 90``                                
2            Config file           ``ci: { threshold: 80 }`` in ``.flareinspect.yml``
3            Environment variable  ``CLOUDFLARE_TOKEN``                              
4 (lowest)   Built-in default      ``concurrency: 3``                                
===========  ====================  ==================================================

Example: Threshold Resolution
------------------------------

Suppose all three sources provide a threshold value:

- CLI: ``--threshold 90``
- Config file: ``ci: { threshold: 80 }``
- Default: no threshold

FlareInspect uses **90** because the CLI flag takes precedence. If ``--threshold`` is omitted, the config file value of **80** is used. If neither is set, there is no threshold gate.

Example: Token Resolution
---------------------------

- CLI: ``--token abc123``
- Config file: ``token: $CLOUDFLARE_TOKEN``
- Environment: ``CLOUDFLARE_TOKEN=xyz789``

FlareInspect uses **abc123** from the CLI. Without the CLI flag, it reads the config file, interpolates ``$CLOUDFLARE_TOKEN`` to **xyz789**, and uses that.

Merging Behavior
-----------------

Settings are merged per-key, not replaced wholesale. A CLI flag overrides only the specific key it targets — all other keys continue to be resolved from the config file or defaults. For example, passing ``--checks dns,ssl`` on the CLI overrides only the checks list while the concurrency, zones, and other settings still come from the config file.
