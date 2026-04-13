=============
API Reference
=============

The FlareInspect web dashboard exposes a REST API for programmatic access to assessments, compliance reports, and exports.

Base URL
--------

By default the dashboard runs at ``http://127.0.0.1:<PORT>``. The port is displayed on startup (or set via the ``PORT`` environment variable).

Authentication
--------------

If ``FLAREINSPECT_API_KEY`` is set, all API requests must include:

.. code-block:: text

   X-API-Key: <your-api-key>

Endpoints
---------

.. list-table::
   :header-rows: 1
   :widths: 40 15 45

   * - Endpoint
     - Method
     - Description
   * - ``/api/assessments``
     - GET
     - List all saved assessments
   * - ``/api/assessments/:id``
     - GET
     - Get a specific assessment by UUID
   * - ``/api/assess``
     - POST
     - Run a new assessment
   * - ``/api/compliance/:id/:framework``
     - GET
     - Get compliance report for an assessment
   * - ``/api/diff``
     - POST
     - Compare two assessments for drift
   * - ``/api/export/:id/:format``
     - GET
     - Download an assessment in a specific format

Content Type
-------------

All POST endpoints accept and return ``application/json``. GET endpoints for exports return the appropriate content type for the requested format.
