==================

HTML Export Format

==================




Generates a standalone, interactive HTML report suitable for management

review and audit evidence.



Usage


----


.. code-block:: bash


    flareinspect export -i assessment.json -f html -o report.html




Report Sections


----


The HTML report includes these sections:


1. **Executive Summary** — score, grade, risk level, top risks

2. **Account Overview** — account details, subscription, domain portfolio

3. **Security Posture** — category breakdown, risk distribution chart

4. **Critical Findings** — detailed table of critical-severity failures

5. **High Risk Findings** — detailed table of high-severity failures

6. **Detailed Findings Review** — per-category findings with evidence

7. **Identity and Access Analysis** — MFA, admin access, token audit

8. **Zone Exposure Analysis** — DNS, proxy, and attack surface

9. **Transport and TLS Analysis** — SSL mode, TLS version, HSTS

10. **Traffic Protection Analysis** — WAF, rate limiting, bot management

11. **Logging and Forensics Analysis** — audit logs, logpush

12. **Recommendations** — prioritized remediation roadmap



Features


----


- Score visualization with circular progress indicator

- Risk distribution bar chart

- Category breakdown chart

- Domain-by-domain findings

- Expandable evidence details


The report uses Handlebars templating from ``templates/report.html``.

