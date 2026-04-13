=====================

Environment Variables

=====================




FlareInspect reads several environment variables for configuration and credentials. These are useful in CI/CD pipelines and container environments where CLI flags are inconvenient.


========================  ============================================================  =============================

   Variable                  Description                                                   Default

========================  ============================================================  =============================

   ``CLOUDFLARE_TOKEN``        Cloudflare API token used when ``--token`` is not provided      —

   ``LOG_LEVEL``               Logging verbosity: ``error``, ``warn``, ``info``, ``debug``           ``info``

   ``CLOUDFLARE_DEBUG``        Enable Cloudflare SDK debug output (``true``/``false``)           ``false``

   ``DEBUG``                   Alias for ``CLOUDFLARE_DEBUG`` when set to ``true``               —

   ``DEFAULT_OUTPUT_DIR``      Default directory for assessment output files                 ``.`` (current directory)

   ``QUIET_MODE``              Suppress banner and non-essential output (``true``/``false``)     ``false``

   ``NO_BANNER``               Skip the startup banner (``true``/``false``)                      ``false``

   ``HOST``                    Host address for the web dashboard server                     ``127.0.0.1``

   ``PORT``                    Port for the web dashboard server                             ``0`` (random available port)

   ``FLAREINSPECT_API_KEY``    API key required for web dashboard authentication when set    —

========================  ============================================================  =============================


Usage Examples


----


.. rubric:: Set the API Token via Environment




.. code-block:: bash


    export CLOUDFLARE_TOKEN=your_cloudflare_api_token

    flareinspect assess




.. rubric:: Run the Web Dashboard on a Specific Host and Port




.. code-block:: bash


    HOST=0.0.0.0 PORT=3000 node web/server.js




.. rubric:: Enable Debug Logging




.. code-block:: bash


    CLOUDFLARE_DEBUG=true flareinspect assess --token $CLOUDFLARE_TOKEN




.. rubric:: Secure the Dashboard with an API Key




.. code-block:: bash


    FLAREINSPECT_API_KEY=your-secret-key node web/server.js



All API requests to the dashboard must then include the ``X-API-Key`` header with the matching value.

