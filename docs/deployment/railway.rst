=======
Railway
=======

Deploy to Railway with the 1-click button.

1-Click Deploy
---------------

`Deploy on Railway <https://railway.app/template/flareinspect>`__

Free tier includes:

- $5 trial credit
- Pay-as-you-go pricing (~$2-5/month for light usage)

Steps
-----

1. Click the Deploy button
2. Sign in with GitHub
3. Railway auto-detects Node.js
4. Add environment variables in Railway dashboard

Environment Variables
----------------------

Set in the Railway dashboard:

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

Access the Dashboard
---------------------

.. code-block:: text

   https://your-app.railway.app
