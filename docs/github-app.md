# Tempus GitHub App

Tempus can execute signed permits as a GitHub App installation. The existing
Gate, agent signatures, atomic permit consumption and signed outcomes remain the
authorization boundary. The RSA App key stays in the mediated executor process.

This first integration supports `github.create_issue` and
`github.create_pull_request`. Each executor is bound by its operator to one
tenant, installation and repository. Automatic PR checks, webhook onboarding and
a hosted multi-tenant service are not implemented by this integration.

## Register and install

1. In GitHub Settings → Developer settings → GitHub Apps, register an App.
   Use your own available App name and the Tempus project URL as its homepage.
2. Disable the webhook for this executor-only mode; it does not receive events.
3. Grant repository **Issues: Read and write** and **Pull requests: Read and
   write** (metadata read access is implicit). Leave other permissions unset.
   If you only use one action, grant only its matching permission.
4. Install the App on selected repositories. Record its client ID and installation
   ID. Generate an RSA private key and store it outside the repository, accessible
   only to the executor's service account.

Registration and installation are external setup steps; creating these source
files does not create an App in your GitHub account.

## Run a permitted action

Install from this checkout with `python -m pip install -e ".[github-app]"`.
Provision the Gate, registered agent and executor identities using the existing
[mediated execution guide](../README.md), and obtain a signed permit whose
resource is the exact installed repository. Then run:

```bash
tempus-github-executor \
  --permit permit.json \
  --executor-db executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id GATE_PUBLIC_KEY \
  --tenant-id TENANT_ID \
  --app-client-id APP_CLIENT_ID \
  --app-private-key /private/tempus-app.pem \
  --installation-id 123456 \
  --repository owner/repository
```

All four App options are required together. App mode ignores `GITHUB_TOKEN`.
The standard token mode remains available when no App options are supplied.
The GitHub App RSA key is distinct from the Tempus Ed25519 executor identity.

The executor first validates and atomically consumes the Tempus permit. It then
mints an installation token restricted to the configured repository and the
permission needed for that action. Tokens are cached in memory by permission
and refreshed 60 seconds before expiry. Neither tokens nor the private key are
included in signed outcomes. HTTPS redirects are rejected.

Authentication failure produces a signed `FAILED` outcome without sending the
repository write. A timeout or server error during the repository write remains
`UNKNOWN` and is never retried automatically. Do not reuse a consumed permit;
reconcile the outcome before requesting a new one.

Run each tenant binding with separate executor state and identity. Do not run
independent database copies against the same permits: distributed consumption
is outside the current runtime's boundary. Installation revocation is enforced
by GitHub when a token or API action is requested.

## Verification

```bash
python -m pip install -e ".[dev,github-app]"
python -m pytest tests/test_github_app.py tests/test_github_executor.py
```

Tests use a generated RSA key and fake GitHub transports. They cover JWT
signatures, scoped token requests, expiry, repository isolation, credential
failure, and native Tempus permit consumption/replay protection. A live test
requires an App installed on a test repository and a valid signed permit.

References: [GitHub App JWT authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
and [installation access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).
