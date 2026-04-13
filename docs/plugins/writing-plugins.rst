===============

Writing Plugins

===============




Create custom security checks and hooks for FlareInspect.



Plugin Structure


----


.. code-block::


    plugins/

      custom-dns-checks/

        flareinspect-plugin.json

        index.js




Manifest


----


``flareinspect-plugin.json``:



.. code-block:: json


    {

      "name": "custom-dns-checks",

      "version": "1.0.0",

      "description": "Additional DNS security checks",

      "author": "Security Team",

      "main": "index.js"

    }




Plugin Implementation


----


``index.js```:



.. code-block:: javascript


    const { FlareInspectPlugin } = require('../../src/plugins/interface');


    class CustomDNSPlugin extends FlareInspectPlugin {

      constructor(manifest) {

        super(manifest);

      }


      getChecks() {

        return [

          {

            id: 'CUSTOM-DNS-001',

            category: 'dns',

            title: 'Custom DNS Record Check',

            description: 'Check for specific DNS record patterns',

            severity: 'medium',

            compliance: []

          }

        ];

      }


      async postAssess(assessment) {

        // Modify or augment the assessment after it completes

        assessment.customPluginData = { checked: true };

        return assessment;

      }

    }


    module.exports = CustomDNSPlugin;




Hook Lifecycle


----


1. **preAssess** — receives the assessment object before checks run

2. Assessment runs with core + plugin checks

3. **postAssess** — receives the completed assessment for augmentation



Adding Custom Checks


----


Return check definitions from`` getChecks()``. Each check follows the

SecurityBaseline schema:


===============  ========  ===============================================

   Field            Type      Description

===============  ========  ===============================================

   ``id``             string    Unique check identifier (prefix with CUSTOM-)

   ``category``       string    Assessment category

   ``title``          string    Check title

   ``description``    string    What the check evaluates

   ``severity``       string    critical/high/medium/low/informational

   ``compliance``     array     Compliance framework tags

===============  ========  ===============================================


Testing


----


.. code-block:: bash


    # Place plugin in ./plugins/my-plugin/

    npm test -- --runInBand

    node src/cli/index.js assess --token $TOKEN



Check logs for plugin loading and hook execution.

