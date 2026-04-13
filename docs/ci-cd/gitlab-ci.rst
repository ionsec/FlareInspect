=========
GitLab CI
=========
=========

Use FlareInspect in GitLab CI to gate deployments on Cloudflare security posture.

Basic Pipeline
---------------

.. code-block:: yaml

   flareinspect-security:
     stage: test
     image: node:20
     script:
       - npm install
       - node src/cli/index.js assess --token $CLOUDFLARE_TOKEN --ci --threshold 80 --fail-on high
     variables:
       CLOUDFLARE_TOKEN: $CI_CLOUDFLARE_TOKEN

Variable Setup
---------------

1. Go to your project → Settings → CI/CD → Variables
2. Add ``CI_CLOUDFLARE_TOKEN`` with your API token value
3. Mark it as **Masked** and **Protected** for security
