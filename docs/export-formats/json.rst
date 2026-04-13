==================

JSON Export Format

==================




The native FlareInspect output format. Preserves the complete assessment

including all findings, the report model, and the configuration snapshot.



Usage


----


.. code-block:: bash


    flareinspect export -i assessment.json -f json -o output.json




Structure


----


The JSON output includes:


  ====================  ===================================================

   Field                 Description

  ====================  ===================================================

   ``assessmentId``        UUID identifying the assessment

   ``provider``            Always ``cloudflare``

   ``startedAt``           Assessment start timestamp

   ``completedAt``         Assessment end timestamp

   ``status``              ``completed`` or ``failed``

   ``account``             Account ID, name, and type

   ``zones``               Array of zones assessed with plan info

   ``findings``            Full array of check results with evidence

   ``score``               Overall score (0–100) and grade (A–F)

   ``summary``             Counts by severity, service, and status

   ``report``              Report model with analysis sections

   ``configuration``       Snapshot of Cloudflare settings examined

   ``complianceReport``    Compliance mapping (if ``--compliance`` used)

   ``contextualScores``    Contextual scoring data (if ``--sensitivity`` used)

  ====================  ===================================================

This format can be re-imported by FlareInspect for ``diff`` comparisons or

re-exported to other formats.



OCSF Variant


----


Use ``-f ocsf`` to produce an OCSF-oriented JSON document. See :doc:`OCSF format <ocsf>`.

