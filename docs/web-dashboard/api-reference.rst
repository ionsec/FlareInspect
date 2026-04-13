=============

API Reference

=============




The FlareInspect web dashboard exposes a REST API for running assessments and

retrieving results.



Base URL


----


.. code-block::


    http://{HOST}:{PORT}




Authentication


----


If ``FLAREINSPECT_API_KEY`` is set, all ``/api/*`` endpoints require the

``X-API-Key`` header. See :doc:`Authentication <authentication>`.



Endpoints


----


.. rubric:: Run Assessment




.. code-block::


    POST /api/assess



  ===============  =========  =======================================

   Parameter        Type       Description

  ===============  =========  =======================================

   ``token``          string     Cloudflare API token (required)

   ``zones``          string     Comma-separated zone filter (max 100)

   ``concurrency``    integer    Parallel zone count (1–10, default 3)

   ``checks``         string     Comma-separated check categories

   ``note```           string     Optional note (max 2000 chars)

  ===============  =========  =======================================

**Response:** Assessment JSON object



.. rubric:: Get Latest Assessment




.. code-block::


    GET /api/assessment



**Response:** The most recent assessment JSON object



.. rubric:: List Assessments




.. code-block::


    GET /api/assessments



**Response:** Array of assessment summaries:



.. code-block:: json


    [

      {

        "id": "uuid",

        "status": "completed",

        "startedAt": "2026-04-12T12:00:00Z",

        "accountName": "My Account",

        "score": 82,

        "grade": "B"

      }

    ]




.. rubric:: Get Assessment by ID




.. code-block::


    GET /api/assessments/:id



The`` :id`` parameter must be a valid UUID.


**Response:** Full assessment JSON object



.. rubric:: Get Compliance Report




.. code-block::


    GET /api/compliance/:framework



Supported frameworks: ``cis``, ``soc2``, ``pci``, ``nist``


**Response:** Compliance report object for the specified framework



.. rubric:: Compare Assessments




.. code-block::


    POST /api/diff



  ==============  ========  =====================================

   Parameter       Type      Description

  ==============  ========  =====================================

   ``baselineId``    string    Baseline assessment UUID (required)

   ``currentId``     string    Current assessment UUID (required)

  ==============  ========  =====================================

**Response:** Diff result with regressions, improvements, and drift score



.. rubric:: Download Endpoints



  ==============================  =============

   Endpoint                        Format

  ==============================  =============

   ``GET /api/download/json``        Native JSON

   ``GET /api/download/html``        HTML report

   ``GET /api/download/sarif``       SARIF

   ``GET /api/download/markdown``    Markdown

   ``GET /api/download/csv``         CSV

   ``GET /api/download/asff``        ASFF

  ==============================  =============

Downloads use the most recent assessment.



.. rubric:: Health Check




.. code-block::


    GET /api/health



**Response:**



.. code-block:: json


    {

      "ok": true,

      "uptime": 3600,

      "version": "1.1.0",

      "lastAssessmentAt": "2026-04-12T12:00:00Z",

      "storage": { "ready": true, "error": null },

      "auth": "api-key"

    }




.. rubric:: Inline Report




.. code-block::


    GET /report



Returns the HTML report for the most recent assessment, rendered inline in the

browser.



Rate Limiting


----


API endpoints are rate-limited. Exceeding the limit returns HTTP 429.



Validation


----


- Assessment IDs must match UUID format

- Framework names must be in the allowed set

- Concurrency is capped at 10

- Zone lists are capped at 100 entries

