=====================

GitLab CI Integration

=====================




Use FlareInspect in GitLab CI/CD pipelines.



Example Pipeline


----


.. code-block:: yaml


    stages:

      - security


    cloudflare-assessment:

      stage: security

      image: node:22-alpine

      before_script:

        - npm ci

      script:

        - node src/cli/index.js assess --token $CLOUDFLARE_TOKEN --ci --threshold 80

      after_script:

        - node src/cli/index.js export -i assessment.json -f html -o report.html

      artifacts:

        paths:

          - assessment.json

          - report.html

        when: always

      variables:

        CLOUDFLARE_TOKEN: $CI_CLOUDFLARE_TOKEN




Drift Detection


----


.. code-block:: yaml


    cloudflare-drift:

      stage: security

      script:

        - node src/cli/index.js diff --baseline baseline.json --current assessment.json

      artifacts:

        paths:

          - drift.json




CI Variable Setup


----


Add the Cloudflare token as a CI/CD variable:


1. Go to **Settings** → **CI/CD** → **Variables**

2. Add variable ``CI_CLOUDFLARE_TOKEN`` with your token value

3. Check **Mask variable** and **Protect variable**

