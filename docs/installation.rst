============
Installation
============
============

From Source
-----------

Clone the repository and install dependencies:

.. code-block:: bash

   git clone https://github.com/ionsec/flareinspect.git
   cd flareinspect
   npm install

Run the CLI directly:

.. code-block:: bash

   node src/cli/index.js --version

Or link it globally for convenient access:

.. code-block:: bash

   npm link
   flareinspect --version

Docker
-------

Build the Docker image from the included ``Dockerfile``:

.. code-block:: bash

   docker build -t flareinspect .

Run an assessment with the container, mounting a volume for output files:

.. code-block:: bash

   docker run -it --rm \
     -e CLOUDFLARE_TOKEN=YOUR_CLOUDFLARE_TOKEN \
     -v $(pwd)/output:/app/output \
     flareinspect assess

Run the web dashboard with the container:

.. code-block:: bash

   docker run -it --rm \
     -p 3000:3000 \
     -e CLOUDFLARE_TOKEN=YOUR_CLOUDFLARE_TOKEN \
     -v $(pwd)/data:/app/web/data \
     flareinspect node web/server.js

The ``Dockerfile`` uses a multi-stage build on ``node:22-alpine``, runs as a non-root user, and includes a health check.

Verify Installation
--------------------

Confirm that FlareInspect is installed and working:

.. code-block:: bash

   flareinspect --version

Expected output:

.. code-block:: text

   1.2.0

You can also run a quick help check:

.. code-block:: bash

   flareinspect help

This prints the list of available commands and confirms the CLI is functional.
