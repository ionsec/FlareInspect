==========================

GitHub Actions Integration

==========================




Use FlareInspect in GitHub Actions to assess Cloudflare security on every push

or schedule.



Example Workflow


----


.. code-block:: yaml


    name: Cloudflare Security Assessment


    on:

      push:

        branches: [main]

      schedule:

        - cron: '0 6 * * 1'  # Weekly Monday 6 AM UTC


    jobs:

      assess:

        runs-on: ubuntu-latest

        steps:

          - uses: actions/checkout@v4


          - uses: actions/setup-node@v4

            with:

              node-version: '22'


          - run: npm ci


          - name: Run Assessment

            env:

              CLOUDFLARE_TOKEN: ${{ secrets.CLOUDFLARE_TOKEN }}

            run: |

              node src/cli/index.js assess --ci --threshold 80 --fail-on high


          - name: Export SARIF

            if: always()

            run: |

              node src/cli/index.js assess --token ${{ secrets.CLOUDFLARE_TOKEN }} -o assessment.json

              node src/cli/index.js export -i assessment.json -f sarif -o findings.sarif


          - name: Upload SARIF to Code Scanning

            if: always()

            uses: github/codeql-action/upload-sarif@v3

            with:

              sarif_file: findings.sarif


          - name: Upload Assessment Artifact

            if: always()

            uses: actions/upload-artifact@v4

            with:

              name: flareinspect-assessment

              path: assessment.json




Drift Detection in CI


----


Compare against a stored baseline:



.. code-block:: yaml


    - name: Check Drift

      run: |

        node src/cli/index.js diff \

          --baseline baseline/assessment.json \

          --current assessment.json



Store the baseline as a repository artifact or in a dedicated branch.



Secret Management


----


Add ``CLOUDFLARE_TOKEN`` to your repository secrets:


1. Go to **Settings** → **Secrets and variables** → **Actions**

2. Click **New repository secret**

3. Name: ``CLOUDFLARE_TOKEN``

4. Value: your Cloudflare API token

