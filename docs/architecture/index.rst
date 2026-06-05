============
Architecture
============

.. toctree::
   :maxdepth: 1
   :hidden:

   overview
   data-flow
   module-map
   resource-graph

FlareInspect follows a layered architecture with clear separation
between the CLI, core services, graph engine, integrations, the
web dashboard, and (since v2.0) the MCP server.  The resource graph
is the single source of truth shared by the posture map, the SIEM
shippers, the MCP server, and the notification dispatcher.
