=================

Docker Deployment

=================




FlareInspect ships with a production-ready Dockerfile and Docker Compose

configuration.



Building the Image


----


.. code-block:: bash


    docker build -t flareinspect .



The Dockerfile uses a multi-stage build:


1. **deps stage** — installs production dependencies only (``npm ci --omit=dev``)

2. **runtime stage** — copies node_modules and source, runs as non-root user

   ``flareinspect``



.. rubric:: Image Details



- Base: ``node:22-alpine3.22``

- Init system: ``dumb-init`` for signal handling

- User: non-root ``flareinspect`` user

- Health check: ``node src/cli/index.js --version``

- Entrypoint: ``dumb-init -- node src/cli/index.js``



Running the CLI


----


.. code-block:: bash


    # Show help

    docker run --rm -it flareinspect


    # Run an assessment with output volume

    docker run --rm -v $(pwd)/output:/app/output flareinspect \

      assess --token YOUR_TOKEN --output /app/output/assessment.json




Docker Compose


----


The ``docker-compose.yml`` defines three services:



.. rubric:: CLI Service




.. code-block:: bash


    docker compose run flareinspect assess --token YOUR_TOKEN




.. rubric:: Web Dashboard Service




.. code-block:: bash


    docker compose up flareinspect-web



Exposes port 3000. Mounts ``./web/data`` for persistent assessment storage.



.. rubric:: Development Service




.. code-block:: bash


    docker compose run flareinspect-dev



Interactive shell with source mounted for development.



Environment Variables


----


Pass environment variables through Compose or ``docker run``:



.. code-block:: bash


    docker run --rm -e CLOUDFLARE_TOKEN=$TOKEN -v $(pwd)/output:/app/output \

      flareinspect assess --output /app/output/report.json




Volumes


----


  =================  ==================================

   Path               Purpose

  =================  ==================================

   ``/app/output``      Assessment result files

   ``/app/logs``        Application logs

   ``/app/web/data``    Web dashboard assessment storage

  =================  ==================================
