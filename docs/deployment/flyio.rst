======
Fly.io
======
======

Deploy to Fly.io for edge deployment with health checks and auto-scaling.

Prerequisites
--------------

Install `Fly CLI <https://fly.io/docs/hands-on/install-flyctl/>`__.

Deploy Commands
----------------

.. code-block:: bash

   # Clone and deploy
   git clone https://github.com/ionsec/flareinspect.git
   cd flareinspect
   fly launch --no-deploy
   fly deploy

   # Set environment variables
   fly secrets set CLOUDFLARE_TOKEN=your_token
   fly secrets set FLAREINSPECT_API_KEY=$(openssl rand -hex 32)

   # Open the app
   fly open

Free Allowance
--------------

3 shared-cpu-1x VMs (256 MB each).

Access the Dashboard
---------------------

.. code-block:: text

   https://your-app.fly.dev
