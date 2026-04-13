=======
Render
=======

Deploy to Render with the 1-click button or manual configuration.

1-Click Deploy
--------------

`Deploy to Render <https://render.com/deploy?repo=https://github.com/ionsec/flareinspect>`__

Free tier includes:

- 512 MB RAM
- Shared CPU
- 1 GB persistent storage for assessment history
- Automatic HTTPS

Steps
-----

1. Click the Deploy button above
2. Connect your GitHub account
3. Environment variables are pre-configured
4. Click "Apply" — deployment takes ~3 minutes

Environment Variables
----------------------

Set in the Render dashboard:

.. list-table::
   :header-rows: 1
   :widths: 35 10 55

   * - Variable
     - Required
     - Description
   * - ``CLOUDFLARE_TOKEN``
     - No
     - Cloudflare API token (can supply via UI)
   * - ``FLAREINSPECT_API_KEY``
     - No
     - API key for dashboard authentication
   * - ``LOG_LEVEL``
     - No
     - Logging level (default: ``info``)

Access the Dashboard
---------------------

.. code-block:: text

   https://your-app.onrender.com
