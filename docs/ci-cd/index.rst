CI/CD Integration
================

.. toctree::
   :maxdepth: 1
   :hidden:

   github-actions
   gitlab-ci
   exit-codes

Use FlareInspect in your CI/CD pipeline to gate deployments on security posture.

.. code-block:: yaml

   - name: Cloudflare Security Assessment
     run: |
       flareinspect assess --token ${{ secrets.CLOUDFLARE_TOKEN }} \
         --ci --threshold 80 --fail-on high

See :doc:`exit-codes` for the full exit code reference.
