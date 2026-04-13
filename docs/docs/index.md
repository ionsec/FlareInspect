---
hide:
  - navigation
  - toc
---

# FlareInspect

<style>
.hero-wrap {
  text-align: center;
  padding: 48px 24px 40px;
}
.hero-wrap img {
  width: 96px;
  margin: 0 auto 20px;
  display: block;
}
.hero-wrap h1 {
  font-family: 'Inter', 'Segoe UI', sans-serif;
  font-size: clamp(2rem, 5vw, 3.2rem);
  font-weight: 800;
  color: #0d1117;
  margin: 0 0 8px;
  letter-spacing: -1px;
}
.hero-wrap .subtitle {
  font-size: 1.1rem;
  color: #6b7280;
  max-width: 600px;
  margin: 0 auto 24px;
  line-height: 1.6;
}
.badges {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 10px;
  margin-bottom: 28px;
}
.badges a { display: contents; }
.badges img {
  height: 22px !important;
  border-radius: 4px;
}
.features-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin: 32px 0;
  text-align: left;
}
.feature-card {
  background: #f9fafb;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 18px 20px;
}
.feature-card h3 {
  font-size: 0.95rem;
  font-weight: 700;
  color: #111827;
  margin: 0 0 6px;
}
.feature-card p {
  font-size: 0.82rem;
  color: #6b7280;
  margin: 0;
  line-height: 1.5;
}
.quick-links {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 12px;
  margin: 24px 0;
}
.quick-links .md-button {
  background: #f6821f !important;
  color: #fff !important;
  border-color: #f6821f !important;
  font-weight: 600;
}
.quick-links .md-button:hover {
  background: #e0731a !important;
}
</style>

<div class="hero-wrap">

  <img src="assets/flare-inspect-logo.svg" alt="FlareInspect logo" />

  <h1>FlareInspect</h1>
  <p class="subtitle">
    Open-source Cloudflare security assessment CLI and web dashboard — scan your infrastructure, detect posture drift, and generate compliance reports for auditors and CI/CD pipelines.
  </p>

  <div class="badges">
    <a href="https://github.com/ionsec/flareinspect/actions"><img src="https://img.shields.io/badge/node-%3E%3D20.0.0-green?style=flat-square" alt="Node.js ≥20" /></a>
    <img src="https://img.shields.io/badge/version-1.2.0-orange?style=flat-square" alt="v1.2.0" />
    <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT" />
    <a href="https://pypi.python.org/python"><img src="https://img.shields.io/badge/docs-ReadTheDocs-8B5CF6?style=flat-square" alt="ReadTheDocs" /></a>
  </div>

  <div class="quick-links">
    [:fontawesome-solid-rocket: Get Started](getting-started.md)
    [:fontawesome-solid-terminal: CLI Reference](cli/assess.md)
    [:fontawesome-solid-shield-halved: Security Checks](checks/index.md)
    [:fontawesome-solid-cloud-arrow-up: Deploy](deployment/index.md)
    [:fontawesome-solid-book: Full Documentation :material-arrow-right:](getting-started.md){ .md-button }
  </div>

</div>

<div class="features-grid">

  <div class="feature-card">
    <h3>🔍 40+ Security Checks</h3>
    <p>Comprehensive coverage across DNS, SSL/TLS, WAF, Zero Trust, Workers, API Gateway, Bot Management, and more.</p>
  </div>

  <div class="feature-card">
    <h3>📊 Drift Detection</h3>
    <p>Track posture regressions over time with <code>flareinspect diff</code> between baseline and current runs.</p>
  </div>

  <div class="feature-card">
    <h3>📋 Compliance Mapping</h3>
    <p>Findings mapped to CIS, SOC 2, PCI-DSS, and NIST CSF controls with pass/fail status and evidence.</p>
  </div>

  <div class="feature-card">
    <h3>📄 Multi-Format Export</h3>
    <p>JSON, HTML, OCSF, SARIF, Markdown, CSV, and ASFF — suitable for human review, CI pipelines, and SIEM ingestion.</p>
  </div>

  <div class="feature-card">
    <h3>🌐 Web Dashboard</h3>
    <p>Local web UI with assessment history, score visualization, compliance reports, and one-click downloads.</p>
  </div>

  <div class="feature-card">
    <h3>☁️ 1-Click Cloud Deploy</h3>
    <p>Deploy to Render, Heroku, Railway, or Fly.io in minutes with persistent storage for assessment history.</p>
  </div>

  <div class="feature-card">
    <h3>🚀 CI/CD Ready</h3>
    <p>Exit codes, configurable threshold gates, and SARIF output for GitHub Actions, GitLab CI, and any pipeline.</p>
  </div>

  <div class="feature-card">
    <h3>🔌 Plugin Support</h3>
    <p>Scaffold trusted local extensions to add custom checks, exporters, or integrations tailored to your environment.</p>
  </div>

</div>

<script>
  // Auto-redirect / to /en/latest/ equivalent on hosted RTD
  const base = '/en/latest/';
  if (location.pathname === '/') {
    // RTD injects language/version — let it handle routing
  }
</script>
