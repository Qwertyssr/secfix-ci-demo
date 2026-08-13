# secfix-ci-demo

A **CI/CD security auto-fix agent**. It runs *after* your security scanners
(**Black Duck** SCA + **Fortify** SAST), and when they report vulnerabilities it
**generates validated fixes** and **opens a Pull Request** — no background daemon,
it lives entirely inside your pipeline.

> Scan → find vulnerabilities → auto-fix on a branch → validate (tests + re-check)
> → open a PR for human review.

This repository is both the **reusable agent** (`secfix/`) and a **sample
vulnerable app** (`sample_app/`) used to demonstrate and test it end to end.

---

## What it does (proven by the local test run)

Running the agent against the sample app fixed **8/8 findings** and kept all
tests green:

```text
secfix v0.1.0: 8 findings, 8 within severities ['critical', 'high', 'medium']
  [deps] PyYAML 5.3 -> 5.4 (CVE-2020-14343)
  [deps] requests 2.19.1 -> 2.20.0 (CVE-2018-18074)
  [deps] Jinja2 2.10 -> 2.10.1 (CVE-2019-10906)
  [deps] urllib3 1.24.1 -> 1.24.2 (CVE-2019-11324)
  [rule] fixed Insecure Deserialization in sample_app/config_loader.py
  [rule] fixed Command Injection in sample_app/tasks.py
  [rule] fixed SQL Injection in sample_app/db.py
  [rule] fixed Weak Cryptographic Hash in sample_app/auth.py
tests: PASS (python -m unittest discover -s sample_app/tests)
OK  PyYAML CVE-2020-14343   ...   OK  Weak Cryptographic Hash (auth.py:15)
```

| Finding | Scanner | Fix applied |
| --- | --- | --- |
| CVE-2020-14343 (PyYAML) | Black Duck | `PyYAML==5.3` → `5.4` |
| CVE-2018-18074 (requests) | Black Duck | `requests==2.19.1` → `2.20.0` |
| CVE-2019-10906 (Jinja2) | Black Duck | `Jinja2==2.10` → `2.10.1` |
| CVE-2019-11324 (urllib3) | Black Duck | `urllib3==1.24.1` → `1.24.2` |
| Weak Cryptographic Hash | Fortify | `hashlib.md5(...)` → `hashlib.sha256(...)` |
| Insecure Deserialization | Fortify | `yaml.load(x, Loader=...)` → `yaml.safe_load(x)` |
| Command Injection | Fortify | `subprocess.call(cmd, shell=True)` → arg-list, no shell |
| SQL Injection | Fortify | string-built SQL → parameterized query |

## Repository layout

```text
secfix-ci-demo/
├── sample_app/                 vulnerable Python app + offline tests
│   ├── auth.py db.py tasks.py config_loader.py
│   ├── requirements.txt        vulnerable deps
│   └── tests/test_app.py       behaviour tests (must stay green after fixes)
├── secfix/                     the agent (zero runtime deps; stdlib only)
│   ├── models.py               common Finding schema + fingerprint
│   ├── normalize.py            Black Duck + Fortify adapters
│   ├── fixers/
│   │   ├── deps.py             requirements.txt version bumper (SCA)
│   │   ├── rules.py            deterministic SAST templates
│   │   ├── sast.py             Vertex AI (Gemini) provider (optional)
│   │   └── code.py             AI-first, rule-fallback, verify residue
│   ├── validate.py             run tests + confirm findings resolved
│   ├── github_pr.py            git branch/commit/push + open PR (REST)
│   └── cli.py                  the pipeline entry point
├── scan_reports/               simulated Black Duck + Fortify JSON
├── tests/
│   ├── test_agent.py           agent unit tests
│   └── test_pipeline_e2e.py    full pipeline simulation (git + mock GitHub API)
└── .github/
    ├── workflows/
    │   └── security-fix.yml     scan → conditional secfix fix PR
```

## Quickstart (local)

```bash
# 1) run the agent's own tests
py -m unittest tests.test_agent -v

# 2) dry-run the full pipeline on a throwaway copy
py -m secfix --root . \
  --blackduck scan_reports/blackduck.json \
  --fortify   scan_reports/fortify.json \
  --req sample_app/requirements.txt \
  --severities critical,high,medium \
  --test-cmd "py -m unittest discover -s sample_app/tests" \
  --pr-body-out pr-body.md
```

> On Windows use `py`; in CI (Linux) use `python`.

## In CI

The pipeline in [.github/workflows/security-fix.yml](.github/workflows/security-fix.yml)
runs on pushes to `main`. It uses the committed demo Black Duck/Fortify reports
as the scan output for now, lets the scan step report whether actionable
vulnerabilities exist, and only then calls `secfix --open-pr`.

### Documentation

| Doc | Contents |
| --- | --- |
| [docs/REFERENCE.md](docs/REFERENCE.md) | **Complete reference** — every module, the `Finding` model, fixers, live API clients, validation, publishers, all CLI flags, exit codes, hard-case behaviour, testing, security |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | **Black Duck + Fortify + CI/CD integration** — live vs file mode, tokens/endpoints, GitHub/GitLab/Jenkins, Vertex AI, troubleshooting |
| [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) | flow diagrams and pipeline internals |
| [docs/REUSE.md](docs/REUSE.md) | quick cheatsheet to drop it into another repo |

### Hard / complex scans

[hard_demo/](hard_demo) contains fixtures with vulnerability classes the agent
**cannot safely auto-fix** (XXE, SSRF, pickle, eval, path traversal, hardcoded
secret, f-string SQLi) plus tricky SCA cases (multi-CVE component, transitive
dep, no-fix-available). [tests/test_hard_cases.py](tests/test_hard_cases.py)
proves the agent fixes the 4 verifiable issues and **escalates the other 9**
into the PR body instead of guessing. See
[docs/REFERENCE.md §7](docs/REFERENCE.md#7-hard-cases--escalation-tested).

### Multiple languages

secfix isn't Python-only. [multilang_demo/](multilang_demo) contains a polyglot
project (npm `package.json`, Maven `pom.xml`, Go `go.mod`, plus JavaScript, Java
and Go source). [tests/test_multilang.py](tests/test_multilang.py) proves the
agent bumps **npm + Maven + Go** dependencies and applies the **weak-hash fix in
JavaScript, Java and Go** — leaving unrelated entries untouched:

```text
[deps] lodash 4.17.11 -> 4.17.21 (npm)      [deps] log4j-core 2.14.1 -> 2.17.1 (maven)
[deps] minimist 1.2.0 -> 1.2.6  (npm)       [deps] gopkg.in/yaml.v2 2.2.2 -> 2.2.8 (go)
[rule] fixed Weak Cryptographic Hash in crypto_util.js / Hasher.java / hash.go
```

### Testing the pipeline without a GitHub runner

`tests/test_pipeline_e2e.py` reproduces the whole CI job locally: it builds a git
repo with a bare `origin`, stands up a **mock GitHub REST API** (the agent honours
`GITHUB_API_URL`), and runs `python -m secfix --open-pr` exactly as the workflow
does — then asserts the fixes were applied, a `secfix/auto-*` branch was pushed,
and the PR was created with the right base/head/body. All suites pass locally:

```text
tests/ (agent + scanner-clients + pipeline + hard + multilang)   20 tests   OK
sample_app/tests                                                  4 tests   OK
workflow YAML   security-fix.yml  parse OK
```

## Security notes

- The agent needs a **`GITHUB_TOKEN`** with `contents:write` + `pull-requests:write`
  to push a branch and open a PR. It never merges protected branches.
- Scanner tokens (`BD_API_TOKEN`, `FORTIFY_TOKEN`) and the Vertex AI service
  account (`GCP_SA_KEY`) live **only** in encrypted CI secrets, never in code.
- AI-generated SAST patches are **always** validated (build + tests + residue
  re-check) before a PR is opened; the rule engine is the trusted fallback.

## Creating the GitHub repo

This folder is a ready-to-push repo. From `secfix-ci-demo/`:

```bash
git init -b main
git add .
git commit -m "secfix: CI security auto-fix agent + sample app"
git remote add origin https://github.com/<owner>/secfix-ci-demo.git
git push -u origin main
```

Then add repo secrets (Settings → Secrets and variables → Actions):
`BD_URL`, `BD_API_TOKEN`, `SSC_URL`, `FORTIFY_TOKEN`, and optionally `GCP_SA_KEY`.
