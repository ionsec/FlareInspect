======
Heroku
======

Deploy to Heroku with the 1-click button.

1-Click Deploy
---------------

`Deploy to Heroku <https://heroku.com/deploy?template=https://github.com/ionsec/flareinspect>`__

Pricing: ~$5/month (Hobby dyno)

Steps
-----

1. Click the Deploy button above
2. Log in to Heroku
3. Configure environment variables (optional)
4. Click "Deploy app"

After Deployment
-----------------

.. code-block:: bash

   # Set your Cloudflare token (optional)
   heroku config:set CLOUDFLARE_TOKEN=your_token

   # Set API key for protection
   heroku config:set FLAREINSPECT_API_KEY=$(openssl rand -hex 32)

   # View logs
   heroku logs --tail

Access the Dashboard
---------------------

.. code-block:: text

   https://your-app.herokuapp.com
