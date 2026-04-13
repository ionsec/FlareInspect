=================

Fly.io Deployment

=================




FlareInspect ships with a ``fly.toml`` configuration for edge deployment on `Fly.io <https://fly.io>`__.



Prerequisites


----


Install the Fly CLI:



.. code-block:: bash


    # macOS / Linux

    curl -L https://fly.io/install.sh | sh


    # Homebrew

    brew install flyctl




Deploy


----


.. code-block:: bash


    git clone https://github.com/ionsec/flareinspect.git

    cd flareinspect


    fly auth login

    fly launch --no-deploy   # reads fly.toml, sets app name

    fly deploy               # builds Docker image and deploys




Set Secrets


----


.. code-block:: bash


    fly secrets set CLOUDFLARE_TOKEN=your_token

    fly secrets set FLAREINSPECT_API_KEY=$(openssl rand -hex 32)



Secrets are stored encrypted in Fly's Vault and injected as environment variables at runtime.



Configuration (``fly.toml``)


----


Key settings in the bundled ``fly.toml``:


===============  =======================================================

   Setting          Value

===============  =======================================================

   Region           ``iad`` (Washington DC — change with ``fly regions add``)

   Instance size    ``shared-cpu-1x`` · 512 MB RAM

   Port             3000 (internal) with ``force_https = true``

   Auto-stop        Enabled when idle to save free allowance

   Health check     ``GET /``` every 30s

===============  =======================================================


Free Allowance


----


Fly.io includes **3 shared-cpu-1x VMs** (256 MB each) at no charge. The 512 MB config above may exceed the free tier; scale down or use the free 256 MB preset to stay within limits.



Persistent Storage


----


.. code-block:: bash


    # Create a volume (1 GB)

    fly volumes create flareinspect_data --region iad --size 1


    # Mount it at /app/web/data in fly.toml

    # Add inside the [[mounts]] section:

    # source    = "flareinspect_data"

    # destination = "/app/web/data"




Useful Commands


----


.. code-block:: bash


    fly status          # instance health

    fly logs            # stream logs

    fly open            # open dashboard URL

    fly scale memory 512  # increase RAM if needed

    fly regions add lhr   # add a London region




Troubleshooting


----


-`` Error: no app name`` — run ``fly launch`` first to create an app entry.

- Deployment times out — check ``fly logs`` for build or startup errors.

- ``403`` on Cloudflare API — verify token scopes.

- Assessment data lost on redeploy — add a persistent volume (see above).

