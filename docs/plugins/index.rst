=======
Plugins
=======
=======

.. toctree::
   :maxdepth: 1
   :hidden:

   writing-plugins

FlareInspect supports trusted local plugins for extending assessment capabilities. Plugins are loaded from the local filesystem and executed within the same process — treat them as a trusted-code boundary, not a sandbox.

Quick Start
-----------

Plugins are discovered from a ``plugins/`` directory relative to the working directory. Each plugin exports a ``register`` function that receives the FlareInspect API.

.. code-block:: bash

   mkdir plugins
   # Add plugin files to plugins/
   flareinspect assess --token $TOKEN
