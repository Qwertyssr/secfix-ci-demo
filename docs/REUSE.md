# Reusing secfix in another CI/CD pipeline

`secfix` is a plain Python package with a CLI. Any pipeline can adopt it in three
steps: **produce scanner JSON → run `python -m secfix` → let it open a PR.**

---

## 1. The contract: scanner report JSON

The agent reads two optional JSON files. Point the adapters at whatever your
scanners produce. The shapes below match the real APIs; the adapters live in
`secfix/normalize.py` and are the *only* place you touch to support a new
scanner or format.

**Black Duck (SCA)** — `normalize_blackduck` expects:
```json
{ "items": [ {
  "componentName": "PyYAML",
  "componentVersionName": "5.3",
  "vulnerabilityWithRemediation": {
    "vulnerabilityName": "CVE-2020-14343",
    "severity": "CRITICAL",
    "solution": "Upgrade to 5.4 or later"
  } } ] }
```
Real source: `GET /api/projects/{id}/versions/{id}/vulnerable-bom-components`.

**Fortify (SAST)** — `normalize_fortify` expects:
```json
{ "data": [ {
  "issueInstanceId": "…",
  "category": "SQL Injection",
  "friority": "Critical",
  "fullFileName": "sample_app/db.py",
  "lineNumber": 13
} ] }
```
Real source: `GET /api/v1/projectVersions/{id}/issues`.

> Using a different tool (Snyk, Trivy, Semgrep, SonarQube)? Add a
> `normalize_<tool>()` in `normalize.py` that returns `Finding` objects. Nothing
> else changes.

## 2. The CLI

```text
python -m secfix
  --root DIR                 repo root to operate on (default ".")
  --blackduck FILE           Black Duck report JSON (omit to skip SCA)
  --fortify FILE             Fortify report JSON (omit to skip SAST)
  --req PATH                 requirements file, relative to root
  --severities LIST          e.g. critical,high (default) or add medium
  --test-cmd "…"             validation command (must exit 0)
  --base BRANCH              PR base branch
  --repo owner/name          GitHub repo (defaults to $GITHUB_REPOSITORY)
  --open-pr                  commit, push and open the PR
  --pr-body-out FILE         write the PR markdown body
  --fail-on-findings         exit 2 if any actionable findings were present
```

Environment: `GITHUB_TOKEN` (required for `--open-pr`); `GITHUB_API_URL` is
honoured for GitHub Enterprise / testing (defaults to `https://api.github.com`);
optional Vertex AI vars `SECFIX_LLM_PROVIDER=vertex`,
`GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_CLOUD_PROJECT`, `VERTEX_LOCATION`,
`VERTEX_MODEL`.

## 3a. GitHub Actions — copy the workflow

Adapt [.github/workflows/security-fix.yml](../.github/workflows/security-fix.yml).
Minimum viable job:

```yaml
permissions: { contents: write, pull-requests: write }
jobs:
  scan-and-fix:
    if: ${{ !startsWith(github.ref_name, 'secfix/') }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: |          # produce scan_reports/*.json from YOUR scanners here
          your-blackduck-export > scan_reports/blackduck.json
          your-fortify-export   > scan_reports/fortify.json
      - run: pip install git+https://github.com/<owner>/secfix-ci-demo@main
      - run: |
          python -m secfix --root . \
            --blackduck scan_reports/blackduck.json \
            --fortify   scan_reports/fortify.json \
            --req requirements.txt \
            --severities critical,high \
            --test-cmd "python -m unittest discover -s tests" \
            --base "${{ github.ref_name }}" \
            --repo "${{ github.repository }}" --open-pr
        env: { GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }} }
```

## 3b. GitHub Actions — use the composite action

Even shorter, via [.github/actions/secfix](../.github/actions/secfix/action.yml):

```yaml
- uses: <owner>/secfix-ci-demo/.github/actions/secfix@main
  with:
    blackduck: scan_reports/blackduck.json
    fortify:   scan_reports/fortify.json
    req:       requirements.txt
    test-cmd:  "python -m unittest discover -s tests"
    open-pr:   "true"
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## 3c. GitLab CI (opens a Merge Request)

`github_pr.py` is GitHub-specific; for GitLab, swap the publish step for the
GitLab MR API (or run without `--open-pr` and let a `glab`/curl step open the MR
from the branch secfix created). Skeleton:

```yaml
security-fix:
  image: python:3.12
  rules: [ { if: '$CI_COMMIT_BRANCH == "main"' } ]
  script:
    - your-blackduck-export > scan_reports/blackduck.json
    - your-fortify-export   > scan_reports/fortify.json
    - pip install git+https://github.com/<owner>/secfix-ci-demo@main
    - python -m secfix --root . --blackduck scan_reports/blackduck.json
        --fortify scan_reports/fortify.json --req requirements.txt
        --severities critical,high --test-cmd "python -m pytest -q"
        --pr-body-out pr-body.md
    - |
      git switch -C "secfix/auto-$CI_PIPELINE_ID"
      git commit -am "security: automated fixes"
      git push -o merge_request.create -o merge_request.target=main \
        "https://oauth2:${GITLAB_BOT_TOKEN}@${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git" HEAD
```

## 3d. Jenkins (declarative)

```groovy
stage('Security fix') {
  when { branch 'main' }
  steps {
    sh 'your-blackduck-export > scan_reports/blackduck.json'
    sh 'your-fortify-export   > scan_reports/fortify.json'
    sh 'pip install git+https://github.com/<owner>/secfix-ci-demo@main'
    withCredentials([string(credentialsId: 'gh-bot', variable: 'GITHUB_TOKEN')]) {
      sh '''python -m secfix --root . \
              --blackduck scan_reports/blackduck.json \
              --fortify   scan_reports/fortify.json \
              --req requirements.txt --severities critical,high \
              --test-cmd "python -m pytest -q" \
              --repo my-org/my-service --open-pr'''
    }
  }
}
```

## Adapting to other ecosystems

`deps.py` currently bumps `requirements.txt`. To support another manifest, add a
bumper that rewrites it and register it in `cli.py`:

| Ecosystem | Manifest | Approach |
| --- | --- | --- |
| Node | `package.json` + lockfile | edit version, then `npm install` to refresh the lock |
| Maven | `pom.xml` | set `<version>` or the managing `<properties>` value |
| Go | `go.mod` | `go get module@vX.Y.Z && go mod tidy` |
| .NET | `*.csproj` | update `<PackageReference Version=…>` |

`rules.py` SAST templates are Python-specific; add language-specific templates or
rely on the Vertex AI provider for other languages (it works on any file, and its
output is still validated by your `--test-cmd`).

## Enabling AI-assisted SAST fixes (Vertex AI)

1. Create/rotate a Google Cloud service account with Vertex AI access.
2. Store its JSON key as the CI secret `GCP_SA_KEY` (never in code).
3. The workflow writes it to a temp file, sets `GOOGLE_APPLICATION_CREDENTIALS`,
   `SECFIX_LLM_PROVIDER=vertex`, `GOOGLE_CLOUD_PROJECT`, and installs
   `google-cloud-aiplatform`.
4. secfix then tries Gemini first for code findings and **verifies** every patch
   before using it; unverifiable patches fall back to the rule engine.

> ⚠️ If a service-account key is ever exposed (e.g. pasted into a chat or log),
> revoke it immediately and issue a new one. Keys belong only in a secret store.

## Operational tips

- Start with `--severities critical,high` and **without** `--open-pr` (report
  only) to build trust, then enable PR creation.
- Keep `--test-cmd` meaningful — it is the safety net that makes auto-fixing safe.
- Rate-limit noise by scoping scanners per service and keeping "one PR per run".
- Require human review on the bot's PRs; consider optional auto-merge only for
  dependency **patch** bumps.
