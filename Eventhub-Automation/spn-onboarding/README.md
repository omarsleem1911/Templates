# PoC — creating the cor. SPN without the PowerShell script

The customer's admin signs in once, and the Hub creates cor.'s SPN in the customer's own tenant — the same steps as `provision-azure-spn-v3.2.ps1`, run through Microsoft Graph with the admin's sign-in instead of the script. It uses the script's capability catalog (same permissions per capability) and ends with its required-permissions check.

- The customer picks capabilities → signs in → **Accept**. Nothing to run, nothing to copy.
- The SPN lives in the **customer's tenant** (single-tenant app owned by the customer).
- cor. holds no app and no permissions of its own: the onboarding app has no permissions, acts only during the sign-in, and is removed from the customer's tenant at the end.
- Covers everything the script does: API permissions, the Message Trace SP, the Exchange Administrator role.
- The connectors do not change: they still receive Tenant ID, Client ID and Client Secret.

Nothing to install: Python 3.10+ standard library only.

## How it works

```
 cor. Hub                                     Microsoft                         customer tenant
 0. "cor. onboarding" app, once:              multi-tenant public client,
    no secret, no permissions                 sign-in with PKCE
 1. admin picks capabilities, signs in   →    consent: manage apps and grants
                                              ON THE ADMIN'S BEHALF, now only
 2. with the admin's token (memory only, this request only), the Hub:
      creates "cor. SPN - Production" (single-tenant) + service principal  →   owned by the customer
      grants its application permissions (= admin consent)
      creates the Message Trace SP (mail flow) / assigns Exchange Administrator (email response)
      creates the client secret
      removes the onboarding app from the tenant (optional, default on)
 3. required-permissions check with the new SPN's own token
```

## The two tenants in the demo

- **cor. tenant** — where the onboarding app is registered (any test tenant where you can register apps).
- **customer tenant** — the tenant being connected (your test tenant, signed in as a Global Administrator).

One tenant can play both roles for a quick run; two tenants show the real cross-tenant flow.

## Run the demo

1. Once, in cor.'s tenant:

   ```bash
   python method2_setup.py register
   ```

   A browser opens to sign in to **cor.'s tenant** (add `--tenant <cor-tenant>` to pick it, or `--device-code`).

2. Start the Hub page:

   ```bash
   python method2_portal.py
   ```

3. Open http://localhost:8401/ and follow the wizard: **Get Started** → **Step 1** choose the capabilities → **Step 2** review every permission (Read-Only / Read-Write, *See details*) → **Next: Authorize with Microsoft**, sign in as the **customer tenant's** Global Administrator and accept.
4. The page lists each step it ran; click **Check the permissions now**. Click it again after a minute if a capability is still pending.
5. Show the result in the customer tenant: **App registrations → cor. SPN (PoC) - Production** (owned by the customer, permissions granted), and **Enterprise applications**: the onboarding app is gone.

### Change a connection

- **Add or remove capabilities:** run the form again with the **same connection name**. The same SPN is updated: same client ID, same secret, and its permissions (and the Exchange role) are changed to match the capabilities chosen, added or removed.
- **Renew the secret:** tick **Renew the secret**. A new secret is created with the chosen validity and the Hub's older ones are removed.
- **Manage:** the start page lists the connections; **manage secrets / delete** signs the admin in again and shows every secret on the app (including ones made outside cor., marking the one the connectors use), with **Remove** per secret and **Delete the SPN**. The admin's token stays in memory for that page only (10 minutes, or until **Finish**), and the onboarding app is removed again at the end.

**Branding:** the pages carry the cor. logo (`corpoc/static/`: drop an official `cor-logo.svg` there to replace the text logo), and `register` and every connection upload `corpoc/static/cor-logo.png` to the app registrations, so Microsoft shows the cor. logo on its consent screen and in Entra.

## What to point out to the team

- The customer types nothing: the tenant ID comes back from Microsoft; the client ID and secret are created by the Hub.
- Least privilege is kept: only the chosen capabilities' permissions; the role-management scope is asked for only when email response is chosen.
- The admin's token is used for this one request and never stored.
- The check page is the script's required-permissions check, run by the Hub after every connection.

## Connect Event Hub (Azure logs)

The automated version of `eventhub-steps-manual.pdf`, **separate from the Microsoft 365 flow**: its own process
(`python eventhub_portal.py`), no Graph code. It reuses only the
`cor. onboarding (PoC)` sign-in app.

The customer only signs in, authorizes, fills in the Azure form and approves the deployment. COR does the rest:

```
 1. Sign in with Microsoft (cor. onboarding app)   -> consent: Azure Resource Manager as the admin
                                                       (user_impersonation + offline_access, nothing else)
 2. "Deploy to Azure" -> cor.'s form in the portal -> Review + create -> namespace, event hub, corehSAS,
                                                       storage account, corcontainer (tagged with the connection ID)
 3. COR, in the background (one access token, memory only, no refresh token, at most ~60 min):
      finds the deployment by its tag, waits until it succeeds
      -> listKeys: Event Hub connection string (corehSAS) + storage connection string (key1)
      -> key expiry: Event Hub SAS keys never expire; storage key1 creation date + expiration policy
      -> Entra ID diagnostic setting "corlogging" (if the admin is Global / Security Administrator)
      -> optional: activity log of every subscription
      -> discards the admin's sign-in, then tests the connection (the test needs no Azure access)
 4. The Hub page updates by itself: progress, errors, results, and a "Test connection" button.
```

**Redirect URI**: production gives the Event Hub flow its own redirect URI on the onboarding app
(`python method2_setup.py register` adds `http://localhost:8402/eh/callback`; it needs a sign-in to cor.'s tenant).
Until then the PoC reuses the URI the app already has (`http://localhost:8401/m2/callback`): `eventhub_portal.py`
then listens on port 8401 and serves that callback itself, so stop `method2_portal.py` while it runs.

**Who signs in**: Owner or Contributor on the subscription (deploy + `listKeys`). Global Administrator or Security
Administrator to stream the Entra ID logs; without it the rest still completes and the page says so.

**Admin access is not kept**: the sign-in asks only for `openid profile` + ARM `user_impersonation`, without
`offline_access`, so Microsoft issues no refresh token. COR holds the single access token in memory (one dict entry
per onboarding, no MSAL, no token cache, never written to disk, logs or the browser) and discards it when the strings
are retrieved, or when the onboarding fails, hits the time limit, or the admin clicks **Cancel and discard the sign-in**.
The record keeps only when and why (`signInDiscardedAt`, `signInDiscardedReason`). After that COR cannot get a new
Azure token without the admin signing in again: it has no refresh token, no client secret, and the onboarding app has
no Azure role of its own. A token Microsoft already issued stays valid until it expires (~60-90 min); the admin's
consent to the onboarding app stays in the tenant until the admin removes the app from Enterprise applications.

**Test connection** uses only the two connection strings, as the connector does: it reads the event hub with a SAS
token signed by the policy key, and the checkpoint container's properties signed with the storage key (Shared Key).

**Secrets (PoC vs production)**: no connection string is in the template Outputs (so not in Azure's deployment
history), in the progress/status responses or in the server log (query strings are not logged). The PoC keeps them in
`state/eventhub-conn/` (git-ignored) and shows them on the result page behind **Show**; production stores them in
COR's secret store instead.

**Template URL**: Azure Resource Manager downloads the template itself at deployment and refuses `localhost`
(`InvalidContentLink`), so the template is published at
https://raw.githubusercontent.com/omarsleem1911/Templates/main/eventhub/azuredeploy.json (repo `omarsleem1911/Templates`,
local clone in `../Templates`) and set in `eventhub/settings.json` (`templateUrl`; the `COR_TEMPLATE_URL` environment
variable overrides it). The portal form (`createUiDefinition.json`) is read only by the admin's browser, so the local
portal serves it, with the connection ID in it. **After changing `eventhub/azuredeploy.json`, copy it to
`../Templates/eventhub/` and push**, or Azure keeps deploying the old version.

| File | Purpose |
|---|---|
| `eventhub_portal.py` | Entry point (port 8402) |
| `corpoc/eventhub.py` | Pages, sign-in, background retrieval, Entra ID diagnostics, connection test |
| `eventhub/azuredeploy.json` | ARM template (PDF steps 1-8, storage key expiration policy, no secrets in outputs) |
| `eventhub/createUiDefinition.json` | The portal form (name availability checks, advanced defaults) |
| `eventhub/settings.json` | Public template URL (`templateUrl`) |

## Known limits and things to test

| Item | Status |
|---|---|
| Who can accept | Global Administrator or Privileged Role Administrator. Cloud Application Administrator cannot grant Microsoft Graph application permissions. |
| Unverified publisher | The consent screen shows "unverified" until cor. completes Microsoft publisher verification (Microsoft partner program). |
| Secret | Created during the sign-in and passed to the Hub once; the customer owns the app and can rotate or delete it. Renewal before expiry needs the admin to sign in again. |
| Azure resources | Covered by the separate **Connect Event Hub** flow (`eventhub_portal.py`, below). |
| Response capabilities | Granted and checked by name only; the PoC never calls a write API. |
| Defender for Endpoint | Skipped automatically when the tenant has no MDE (its API is not in the tenant). |
| SharePoint | Not verified by the PoC (SharePoint app-only needs a certificate). |

## Production notes (not in the PoC)

- The redirect URI becomes the Hub's HTTPS address instead of `localhost`.
- The secret goes to the connector's credential store, not to a file.
- State (`state/`) stands in for the Hub database and holds secrets: it is git-ignored.

## Microsoft references

| Step | Source |
|---|---|
| Admin sign-in (delegated, PKCE) | [OAuth 2.0 authorization code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow) |
| Onboarding app works with any tenant | [Multi-tenant apps](https://learn.microsoft.com/en-us/entra/identity-platform/howto-convert-app-to-be-multi-tenant) |
| Create the app registration | [Create application](https://learn.microsoft.com/en-us/graph/api/application-post-applications) |
| Create its service principal | [Create servicePrincipal](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-serviceprincipals) |
| Grant the permissions (admin consent) | [Grant an appRoleAssignment](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-approleassignedto), [Grant admin consent — Microsoft Graph](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent?pivots=ms-graph) |
| Create the secret | [application: addPassword](https://learn.microsoft.com/en-us/graph/api/application-addpassword) |
| Assign the Exchange role | [Create roleAssignment](https://learn.microsoft.com/en-us/graph/api/rbacapplication-post-roleassignments) |

## Files

| File | Purpose |
|---|---|
| `method2_setup.py` | Register / show / remove the onboarding app in cor.'s tenant |
| `method2_portal.py` | Capability form, sign-in, provisioning steps, permissions check (port 8401) |
| `corpoc/` | Shared: capability catalog, sign-in, Graph operations, verification, page layout |
