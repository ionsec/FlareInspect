==========
Deployment
==========

.. toctree::
   :maxdepth: 1
   :hidden:

   docker
   render
   heroku
   railway
   flyio
   standalone

Deploy FlareInspect to cloud platforms with 1-click buttons or minimal configuration.

Quick Deploy
------------

.. list-table::
   :header-rows: 1
   :widths: 20 55 25

   * - Platform
     - Link
     - Cost
   * - Render
     - `Deploy <https://render.com/deploy?repo=https://github.com/ionsec/flareinspect>`__
     - Free tier
   * - Heroku
     - `Deploy <https://heroku.com/deploy?template=https://github.com/ionsec/flareinspect>`__
     - ~$5/month
   * - Railway
     - `Deploy <https://railway.app/template/flareinspect>`__
     - $5 trial
   * - Fly.io
     - :doc:`flyio`
     - Free allowance

Environment Variables
---------------------

========================  ========  ========================================
Variable                  Required  Description                             
========================  ========  ========================================
``CLOUDFLARE_TOKEN``      No        Cloudflare API token (can supply via UI)
``FLAREINSPECT_API_KEY``  No        Protect dashboard with X-API-Key header 
``NODE_ENV``              No        Set to ``production`` (default)         
``LOG_LEVEL``             No        Logging level (default: ``info``)       
``HOST``                  No        Bind address (default: ``0.0.0.0``)     
``PORT``                  No        Port number (default: ``3000``)         
========================  ========  ========================================
