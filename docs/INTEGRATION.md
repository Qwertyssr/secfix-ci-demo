# Integration Guide — Black Duck, Fortify & any CI/CD

How to run `secfix` in **your** pipeline against **your** Black Duck and Fortify.
For the full component reference see [REFERENCE.md](REFERENCE.md).

There are two ways to feed findings to secfix. Pick per scanner — you can mix.

| Mode | You do | secfix does |
| --- | --- | --- |
| **Live API** | give secfix a base URL + token | it queries the scanner REST API directly |
| **File** | run the scanner CLI, emit JSON | it reads the JSON file |

The demo repo's shipped GitHub workflow uses committed sample reports for now,
then lets the scan step decide whether the fixing/PR step should run.
For a real pipeline, replace that scan step with your Black Duck/Fortify export
or call secfix in live API mode.

---

## Part A — Black Duck (SCA)

### A1. What you need
| Item | Where to get it |
| --- | --- |
| **Base URL** | your Black Duck (Hub) server, e.g. `https://blackduck.example.com` |
| **API token** | Black Duck UI → *My Access Tokens* → *Create* → scope **read** (role *Project Viewer* is enough) |
| **Project / version names** | the project + version you scan (e.g. `my-service` / `main`) |

Store the URL + token as CI secrets. The token is exchanged for a short-lived
bearer automatically by secfix.

### A2. Live mode (recommended — no export step)
secfix calls, in order:
```
POST /api/tokens/authenticate          Authorization: token <API_TOKEN>   -> bearerToken
GET  /api/projects?q=name:<project>                                        -> _meta.href
GET  <projectHref>/versions?q=versionName:<version>                        -> _meta.href
GET  <versionHref>/vulnerable-bom-components                              -> items[]
```
Run:
```bash
export BD_API_TOKEN=****
python -m secfix --root . \
  --blackduck-url https://blackduck.example.com \
  --blackduck-project my-service \
  --blackduck-version main \
  --req requirements.txt --severities critical,high
```

### A3. File mode (if you already run Black Duck Detect)
```bash
# run the scan
bash <(curl -s https://detect.blackduck.com/detect10.sh) \
  --blackduck.url="$BD_URL" --blackduck.api.token="$BD_API_TOKEN" \
  --detect.project.name=my-service --detect.project.version.name=main
# export vulnerable components to the shape secfix expects (see REFERENCE §4/§5)
#   -> scan_reports/blackduck.json  (a {"items":[…]} document)
python -m secfix --root . --blackduck scan_reports/blackduck.json --req requirements.txt
```
If your export differs, adapt `normalize_blackduck` in `secfix/normalize.py`.

---

## Part B — Fortify (SAST)

### B1. What you need
| Item | Where to get it |
| --- | --- |
| **SSC base URL** | your Fortify Software Security Center, e.g. `https://ssc.example.com` |
| **Auth token** | SSC → *Administration → Token Management* → create a **CIToken** (or a Unified Login Token) with read access |
| **Application / version** | the app + version in SSC (e.g. `my-service` / `main`) |

The token is sent as `Authorization: FortifyToken <token>`.

### B2. Live mode
secfix calls:
```
GET /api/v1/projectVersions?q=name:<version>     Authorization: FortifyToken <TOKEN>  -> resolve id
GET /api/v1/projectVersions/<id>/issues                                               -> data[]
```
Run:
```bash
export FORTIFY_TOKEN=****
python -m secfix --root . \
  --fortify-url https://ssc.example.com \
  --fortify-app my-service --fortify-version main \
  --severities critical,high
```

### B3. File mode (ScanCentral / fortifyclient)
```bash
# translate + upload a scan (example)
scancentral -sscurl "$SSC_URL" -ssctoken "$FORTIFY_TOKEN" start -upload \
  -application my-service -version main -b build-id
# export issues to JSON secfix understands (a {"data":[…]} document)
fortifyclient -url "$SSC_URL" -authtoken "$FORTIFY_TOKEN" \
  listIssues -application my-service -applicationVersion main -outputFormat json \
  > scan_reports/fortify.json
python -m secfix --root . --fortify scan_reports/fortify.json
```
Adapt `normalize_fortify` if your export shape differs.

### B4. Which Fortify categories get auto-fixed?
Out of the box the deterministic engine fixes **Weak Cryptographic Hash,
Insecure Deserialization (yaml), Command Injection, SQL Injection (concatenated)**.
Everything else (XXE, SSRF, path traversal, eval, hardcoded secrets, f-string
SQLi, …) is **escalated** in the PR body unless you enable the Vertex AI provider
(see Part F). This is by design — see the hard-case walkthrough in
[REFERENCE.md §7](REFERENCE.md#7-hard-cases--escalation-tested).

---

## Part C — GitHub Actions (Pull Requests)

### C1. Minimal workflow
```yaml
name: security-fix
on:
  push: { branches: [main] }
permissions:
  contents: write          # push the fix branch
  pull-requests: write     # open the PR
jobs:
  scan-and-fix:
    if: ${{ !startsWith(github.ref_name, 'secfix/') }}   # don't loop on our own branches
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install git+https://github.com/<owner>/secfix-ci-demo@main
      - name: Run security scans
        id: security-scan
        run: |
          your-blackduck-export > scan_reports/blackduck.json
          your-fortify-export   > scan_reports/fortify.json
          echo "has_vulnerabilities=true" >> "$GITHUB_OUTPUT"
      - name: secfix fix and PR
        if: steps.security-scan.outputs.has_vulnerabilities == 'true'
        env:
          GITHUB_TOKEN:   ${{ secrets.GITHUB_TOKEN }}
        run: |
          python -m secfix --root . \
            --blackduck scan_reports/blackduck.json \
            --fortify scan_reports/fortify.json \
            --req requirements.txt --severities critical,high \
            --test-cmd "python -m pytest -q" \
            --base "${{ github.ref_name }}" --repo "${{ github.repository }}" --open-pr
```

### C2. One-time repo settings
- **Secrets** (Settings → Secrets and variables → Actions → *Secrets*):
  `BD_URL`, `BD_API_TOKEN`, `SSC_URL`, `FORTIFY_TOKEN` (+ optional `GCP_SA_KEY`).
- **Variables** (same page → *Variables*): optional `BD_PROJECT`, `BD_VERSION`,
  `FORTIFY_APP`, `FORTIFY_VERSION`.
- **Allow PR creation:** Settings → Actions → General → Workflow permissions →
  enable **"Allow GitHub Actions to create and approve pull requests"**
  (otherwise the PR call returns **HTTP 403** — see Troubleshooting). Via API:
  ```bash
  gh api -X PUT repos/<owner>/<repo>/actions/permissions/workflow \
    -f default_workflow_permissions=write -F can_approve_pull_request_reviews=true
  ```

> The demo repo's [security-fix.yml](../.github/workflows/security-fix.yml) is the
> simplest starting point: scan reports, scan-owned vulnerability output, then
> conditional `secfix --open-pr`.

---

## Part D — GitLab CI (Merge Requests)

`secfix` has a native GitLab publisher (`--provider gitlab`).

```yaml
security-fix:
  image: python:3.12
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
  variables:
    GIT_STRATEGY: clone
  script:
    - pip install git+https://github.com/<owner>/secfix-ci-demo@main
    - |
      python -m secfix --root . \
        --blackduck-url "$BD_URL" --blackduck-project my-service \
        --fortify-url   "$SSC_URL" --fortify-app     my-service \
        --req requirements.txt --severities critical,high \
        --test-cmd "python -m pytest -q" \
        --provider gitlab --open-pr
  # Requires CI/CD variables: BD_URL, BD_API_TOKEN, SSC_URL, FORTIFY_TOKEN,
  # and GITLAB_TOKEN (a project/group access token with 'api' scope).
```
secfix reads `CI_PROJECT_ID`, `CI_SERVER_URL`, `CI_API_V4_URL` automatically and
opens the MR from the pushed `secfix/auto-*` branch.

---

## Part E — Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('Security fix') {
      when { branch 'main' }
      steps {
        withCredentials([
          string(credentialsId: 'gh-bot',       variable: 'GITHUB_TOKEN'),
          string(credentialsId: 'bd-token',      variable: 'BD_API_TOKEN'),
          string(credentialsId: 'fortify-token', variable: 'FORTIFY_TOKEN')
        ]) {
          sh '''
            pip install git+https://github.com/<owner>/secfix-ci-demo@main
            python -m secfix --root . \
              --blackduck-url "$BD_URL" --blackduck-project my-service \
              --fortify-url   "$SSC_URL" --fortify-app     my-service \
              --req requirements.txt --severities critical,high \
              --test-cmd "python -m pytest -q" \
              --repo my-org/my-service --open-pr
          '''
        }
      }
    }
  }
}
```

---

## Part F — Optional: AI-assisted SAST fixes (Vertex AI / Gemini)

Turns several *escalated* SAST categories into auto-fixes — still validated.

1. Create a Google Cloud **service account** with Vertex AI access; download its
   JSON key.
2. Store the JSON as CI secret `GCP_SA_KEY`. **Never** commit it or paste it into
   chat/logs; if it leaks, **revoke and rotate immediately**.
3. In the job, before running secfix:
   ```bash
   printf '%s' "$GCP_SA_KEY" > "$RUNNER_TEMP/sa.json"
   export GOOGLE_APPLICATION_CREDENTIALS="$RUNNER_TEMP/sa.json"
   export SECFIX_LLM_PROVIDER=vertex GOOGLE_CLOUD_PROJECT=my-gcp-project VERTEX_LOCATION=us-central1
   pip install "google-cloud-aiplatform>=1.60"
   ```
secfix then tries Gemini first for code findings and **verifies** every patch
(residue + your `--test-cmd`) before using it; unverifiable patches fall back to
the rule engine or escalate.

---

## Part G — Secrets & least privilege

| Credential | Scope it needs | Scope it must NOT have |
| --- | --- | --- |
| Black Duck token | read (Project Viewer) | admin / delete |
| Fortify token | read issues | upload/admin/user mgmt |
| Git bot token | push branches + open PR/MR | merge protected branches, delete repo |
| Vertex SA key | Vertex AI user | broad project owner |

Keep all of these in the CI secret store only. The bot opens PRs/MRs; humans (or
a narrowly-scoped, explicitly-enabled auto-merge) complete them.

---

## Part H — Troubleshooting

| Symptom | Cause & fix |
| --- | --- |
| **HTTP 403 opening the PR** | Enable *Allow GitHub Actions to create and approve pull requests* (Part C2). The fix branch is still pushed; just the PR call is blocked. |
| **401 / 403 from Black Duck** | Token expired or wrong role; regenerate a read token. The bearer is short-lived — secfix re-authenticates each run. |
| **401 from Fortify** | Wrong token type; use a **CIToken** with `Authorization: FortifyToken`. |
| **"0 findings"** | Project/version name mismatch, or the scan hasn't completed in SSC/Black Duck. Confirm the exact names and that results exist. |
| **Validation failed (exit 3)** | Your `--test-cmd` failed on the patched tree — the agent correctly refused to open a PR. Inspect the test output. |
| **A CVE wasn't fixed** | It's transitive / not in `requirements.txt`, or has no fixed version → it's **escalated** in the PR body by design. |
| **Duplicate PRs on every run** | This CI-only version has no persistent de-dup. Use `paths-ignore` (shipped) and close superseded PRs, or add a state store keyed by `Finding.fingerprint()`. |
| **Workflow runs on the bot's own branch** | Ensure the `if: !startsWith(github.ref_name, 'secfix/')` guard is present. |

---

## Part I — Rollout recommendation

1. **Report-only** first: run without `--open-pr` (or with `--pr-body-out`) to see
   what it *would* do.
2. Enable `--open-pr` on **one** non-critical service; keep human review required.
3. Start at `--severities critical,high`; widen later.
4. Keep `--test-cmd` meaningful — it's the safety net that makes auto-fixing safe.
5. Consider optional auto-merge only for dependency **patch** bumps that pass CI.
