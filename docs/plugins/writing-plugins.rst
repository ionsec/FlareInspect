===============
Writing Plugins
===============

FlareInspect plugins extend the assessment pipeline with custom check logic.

Plugin Interface
-----------------

Each plugin must export a ``register`` function:

.. code-block:: javascript

   module.exports = {
     register(api) {
       api.addCheck({
         id: 'CUST-001',
         title: 'Custom Security Check',
         category: 'custom',
         severity: 'medium',
         description: 'Checks a custom security property',
         async run(context) {
           const value = await context.cloudflare.get('/some/endpoint');
           return {
             status: value.enabled ? 'PASS' : 'FAIL',
             observed: value.enabled ? 'enabled' : 'disabled',
             expected: 'enabled',
           };
         },
       });
     },
   };

Plugin API
-----------

===============  ====================================================
Method           Description                                         
===============  ====================================================
``addCheck``     Register a custom check with the assessment pipeline
``addCategory``  Register a new check category                       
===============  ====================================================

Check Context
--------------

==============  ========================================================
Property        Description                                             
==============  ========================================================
``cloudflare``  The Cloudflare API client                               
``zone``        The current zone being assessed (null for account-level)
``account``     The current account being assessed                      
==============  ========================================================

Loading Plugins
----------------

Plugins are loaded from the ``plugins/`` directory relative to the working directory. Files must be valid CommonJS modules (``.js``) that export a ``register`` function.

Security Considerations
------------------------

- Plugins run in the same process as FlareInspect with full access to the Cloudflare API client
- Only load plugins from trusted sources
- Plugins can make API calls using the provided token — review plugin code before loading
- There is no sandboxing or permission isolation for plugins
