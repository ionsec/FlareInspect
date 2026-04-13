==========
Exit Codes
==========

FlareInspect uses exit codes to communicate assessment results to CI/CD pipelines.

assess Exit Codes
------------------

======================================================  =========
Condition                                               Exit Code
======================================================  =========
Assessment passes threshold and severity gate           ``0``    
Overall score < ``--threshold`` value                   ``1``    
Any finding at or above ``--fail-on`` severity is FAIL  ``1``    
Assessment itself fails (invalid token, API error)      ``1``    
======================================================  =========

diff Exit Codes
----------------

=====================================  =========
Condition                              Exit Code
=====================================  =========
No regressions detected                ``0``    
One or more regressions detected       ``1``    
Error (invalid input, file not found)  ``1``    
=====================================  =========

Using Exit Codes in Shell
--------------------------

.. code-block:: bash

   flareinspect assess --token $TOKEN --ci --threshold 80
   if [ $? -ne 0 ]; then
     echo "Security gate failed!"
     exit 1
   fi

Using Exit Codes in CI
-----------------------

Most CI systems automatically fail a step when a command exits with a non-zero code. No special handling is needed beyond running the command.
