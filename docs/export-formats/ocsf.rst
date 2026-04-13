==================

OCSF Export Format

==================




Produces a JSON document compliant with the Open Cybersecurity Schema

Framework (OCSF) class 2001 (Security Finding).



Usage


----


.. code-block:: bash


    flareinspect export -i assessment.json -f ocsf -o findings.ocsf.json




Schema Mapping


----


  ====================  =======================================

   FlareInspect Field    OCSF Field

  ====================  =======================================

   Finding severity      ``severity_id`` (1–5), ``severity``

   Finding status        ``status_id`` (1–5), ``status``

   Check ID              ``finding_info.uid``

   Check title           ``finding_info.title``

   Service               ``finding_info.types``

   Resource             `` resources[].uid```,`` resources[].type```

   Description           ``message``, ``description``

   Remediation           ``remediation``

   Timestamp             ``time`` (epoch seconds)

  ====================  =======================================


OCSF Constants


----


  ================  =====================================

   Field             Values

  ================  =====================================

   ``activity_id``     5 (Evaluate)

   ``class_uid``       2001 (Security Finding)

   ``category_uid``    2 (Findings)

   ``type_uid``        200101 (Security Finding: Evaluate)

  ================  =====================================


Severity Mapping


----


  ===============  =============

   FlareInspect     severity_id

  ===============  =============

   critical         5

   high             4

   medium           3

   low              2

   informational    1

  ===============  =============


Observables


----


The OCSF output includes an ``observables`` array with unique resources:

- Zones as ``domain_name`` (type_id 2)

- Account as ``cloud_account`` (type_id 90)

- Security Insights subjects as ``security_insight`` (type_id 99)

