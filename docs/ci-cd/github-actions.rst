==============
GitHub Actions
==============

Use FlareInspect in GitHub Actions to gate deployments on Cloudflare security posture.

Basic Workflow
---------------

.. code-block:: yaml

   name: Cloudflare Security Assessment
   on:
     push:
       branches: [main]
     schedule:
       - cron: "0 6 * * 1"  # Weekly Monday 6 AM UTC

   jobs:
     security:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-node@v4
           with:
             node-version: "20"
         - run: npm install
         - name: Run assessment
           run: |
             node src/cli/index.js assess \
               --token ${{ secrets.CLOUDFLARE_TOKEN }} \
               --ci --threshold 80 --fail-on high
           env:
             CLOUDFLARE_TOKEN: ${{ secrets.CLOUDFLARE_TOKEN }}

With SARIF Upload
------------------

Upload results to GitHub Advanced Security:

.. code-block:: yaml

   - name: Run assessment
     run: |
       node src/cli/index.js assess \
         --token ${{ secrets.CLOUDFLARE_TOKEN }} \
         --ci --output assessment.json
       node src/cli/index.js export \
         -i assessment.json -f sarif -o results.sarif

   - name: Upload SARIF
     uses: github/codeql-action/upload-sarif@v3
     with:
       sarif_file: results.sarif

Secrets Setup
--------------

1. Go to your repository → Settings → Secrets and variables → Actions
2. Add ``CLOUDFLARE_TOKEN`` with your API token value
3. Reference it in workflows as ``${{ secrets.CLOUDFLARE_TOKEN }}``
