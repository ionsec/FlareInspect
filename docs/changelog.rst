=========

Changelog

=========





1.2.0 — 2026-04-13


----


.. rubric:: Cloud Deployment



- **1-Click Deployment** — Deploy to Render, Heroku, Railway, or Fly.io with single-click buttons

- **Heroku Button** — Added ``app.json`` for one-click Heroku deployment with pre-configured environment variables

- **Render Configuration** — Enhanced ``render.yaml`` with 1 GB persistent storage for assessment history

- **Railway Template** — Added ``railway.json`` for Railway deployment with auto-restart policies

- **Fly.io Configuration** — Added ``fly.toml`` for edge deployment with health checks and auto-scaling

- **Deployment Guide** — New ``DEPLOYMENT.md`` with step-by-step instructions for all platforms



.. rubric:: Documentation



- Updated README with version badge, deployment buttons, and cloud hosting options

- Added deployment overview page and dedicated guides for Heroku, Railway, and Fly.io

- Updated index page to include deployment feature row and quick-deploy buttons

- Refreshed ``render.md`` to reflect 1 GB persistent storage



----


1.1.0 — 2026-04-12


----


- Added ``diff`` command for baseline drift detection

- Added compliance mapping for ``cis``, ``soc2``, ``pci``, and ``nist``

- Added contextual scoring and CI/CD gating options for ``assess``

- Added exporters for ``sarif``, ``markdown``, ``csv``, and ``asff``

- Added config file loading via ``.flareinspect.yml``, ``.flareinspect.yaml``, and ``flareinspect.config.json``

- Expanded web API with assessment history, compliance, drift comparison, API key auth, and extra download endpoints

- Added plugin loader scaffolding and automated tests for new modules

- Updated Docker, Render, linting, and repository metadata for a coherent 1.1.0 release

