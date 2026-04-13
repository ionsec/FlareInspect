================================

Cloudflare API Permissions Guide

================================




FlareInspect requires specific Cloudflare API token permissions to assess your

account and zones.



Minimum Permissions


----


These permissions provide basic coverage:


  ======================  =========  ========

   Permission              Scope      Access

  ======================  =========  ========

   Zone                    Zone       Read

   DNS                     Zone       Read

   SSL and Certificates    Zone       Read

   Firewall Services       Zone       Read

   Account Settings        Account    Read

  ======================  =========  ========


Recommended Permissions


----


For broader coverage including Zero Trust, Workers, and audit logs:


  ======================  =========  ========

   Permission              Scope      Access

  ======================  =========  ========

   Zone                    Zone       Read

   DNS                     Zone       Read

   SSL and Certificates    Zone       Read

   Firewall Services       Zone       Read

   Account Settings        Account    Read

   Access: Zero Trust      Account    Read

   Workers Scripts         Account    Read

   Audit Logs              Account    Read

   Security Center         Account    Read

   Logpush                 Account    Read

   API Gateway             Account    Read

  ======================  =========  ========


Creating the Token


----


1. Log in to `Cloudflare Dashboard <https://dash.cloudflare.com>`__

2. Go to **My Profile** → **API Tokens**

3. Click **Create Token**

4. Select **Custom token**

5. Add permissions from the table above

6. Set **Zone Resources** to All zones (or specific zones)

7. Click **Continue to summary** → **Create Token**



Token Troubleshooting


----


  ============================  =========================================================

   Error                         Likely Cause

  ============================  =========================================================

   ``403``                         Token missing required product scopes or entitlements

   ``No matching zones found``     Zone filter excludes all zones or token cannot see them

   ``Unknown check categories``    ``--checks`` included unsupported category names

   Fewer zones than expected     Token scoped to a single account or organization

  ============================  =========================================================


Security Best Practices


----


- Store tokens in environment variables, not in code or config files

- Use the minimum permissions needed for your assessment scope

- Set token expiration dates when possible

- Rotate tokens regularly

- Never share tokens in chat, email, or commit them to git

