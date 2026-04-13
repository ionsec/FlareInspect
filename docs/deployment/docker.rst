======
Docker
======
======

Build and run FlareInspect with Docker.

Build the Image
----------------

.. code-block:: bash

   docker build -t flareinspect .

The ``Dockerfile`` uses a multi-stage build on ``node:22-alpine``, runs as a non-root user, and includes a health check.

Run an Assessment
------------------

.. code-block:: bash

   docker run -it --rm \
     -e CLOUDFLARE_TOKEN=YOUR_CLOUDFLARE_TOKEN \
     -v $(pwd)/output:/app/output \
     flareinspect assess

Run the Web Dashboard
----------------------

.. code-block:: bash

   docker run -it --rm \
     -p 3000:3000 \
     -e CLOUDFLARE_TOKEN=YOUR_CLOUDFLARE_TOKEN \
     -v $(pwd)/data:/app/web/data \
     flareinspect node web/server.js

Docker Compose
---------------

.. code-block:: bash

   docker compose up flareinspect-web

The compose file exposes:

- ``flareinspect`` for CLI execution
- ``flareinspect-web`` for the dashboard at ``http://localhost:3000``
- ``flareinspect-dev`` for interactive development
