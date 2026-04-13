================

Interactive Mode

================




FlareInspect includes an interactive shell for running commands without repeating the full CLI prefix each time.



Starting Interactive Mode


----


Run ``flareinspect`` with no arguments to launch the interactive shell:



.. code-block:: bash


    flareinspect



You will see a banner and a ``flareinspect>`` prompt.



Available Commands


----


===========  ============================================================

   Command      Description

===========  ============================================================

   ``assess``     Run a Cloudflare security assessment (same options as CLI)

   ``export``     Export assessment results to a different format

   ``help``       Display help information

   ``credits``    Display IONSEC.IO information

   ``clear``      Clear the terminal screen

   ``exit``       Exit interactive mode

===========  ============================================================


Passing Options


----


All flags available in CLI mode work inside the interactive shell. For example:



.. code-block::


    flareinspect> assess --token YOUR_CLOUDFLARE_TOKEN --zones example.com




When to Use Interactive Mode


----


- **Exploratory assessments:** Quickly run targeted checks against different zones or categories without re-typing the full command.

- **Debugging:** Use ``--debug`` interactively to inspect API calls and scoring decisions.

- **Ad-hoc workflows:** Chain an ``assess`` then an ``export`` without leaving the shell.


For CI/CD and scripted environments, use the standard CLI commands instead — interactive mode requires a TTY.

