# secfix-ci-demo — Complete Reference

`secfix` is a **CI/CD security auto-fix agent**. It runs *after* your security
scanners (**Black Duck** SCA + **Fortify** SAST), turns their findings into
**validated code changes**, and opens a **Pull Request** (GitHub) or **Merge
Request** (GitLab). It never runs as a background daemon — it lives inside your
pipeline, does its work, and exits.

> Scan → normalize findings → filter by policy → generate fixes → **validate**
> (tests + re-check) → open a PR/MR for human review. Anything it can't fix
> **safely** is escalated, never guessed.

This document covers **every** part of the system with examples. For getting it
into your own pipeline and wiring real Black Duck/Fortify, see
[INTEGRATION.md](INTEGRATION.md). For the internal flow diagrams see
[HOW-IT-WORKS.md](HOW-IT-WORKS.md); for a quick reuse cheatsheet see
[REUSE.md](REUSE.md).

---

## 1. Repository layout

```text
secfix-ci-demo/
├── sample_app/                     easy demo app + offline behaviour tests
│   ├── auth.py                     weak MD5 hash (Fortify)
│   ├── config_loader.py            yaml.load insecure deserialization (Fortify)
│   ├── db.py                       string-built SQL injection (Fortify)
│   ├── tasks.py                    subprocess shell=True command injection (Fortify)
│   ├── requirements.txt            vulnerable deps (Black Duck)
│   └── tests/test_app.py           behaviour tests (must stay green post-fix)
├── hard_demo/                      HARD stress-test fixtures
│   ├── app.py                      XXE, SSRF, pickle, eval, path traversal, secret…
│   ├── requirements.txt            multi-CVE / transitive / no-fix deps
│   └── reports/{blackduck,fortify}.json
├── scan_reports/{blackduck,fortify}.json   simulated reports (real API shapes)
├── secfix/                         the agent (stdlib-only core; zero runtime deps)
│   ├── models.py                   common Finding schema + fingerprint
│   ├── normalize.py                Black Duck + Fortify adapters (raw JSON → Finding)
│   ├── scanners/
│   │   ├── blackduck_client.py     LIVE Black Duck REST client
│   │   ├── fortify_client.py       LIVE Fortify SSC REST client
│   │   └── gather.py               choose live-API vs file, return Findings
│   ├── fixers/
│   │   ├── deps.py                 SCA: requirements.txt version bumper
│   │   ├── rules.py                SAST: deterministic templates
│   │   ├── sast.py                 SAST: Vertex AI (Gemini) provider (optional)
│   │   └── code.py                 SAST orchestrator (AI → rules → verify)
│   ├── validate.py                 run tests + confirm findings resolved
│   ├── git_ops.py                  branch / commit / push (shared)
│   ├── github_pr.py                open GitHub PR (REST)
│   ├── gitlab_mr.py                open GitLab MR (REST)
│   └── cli.py                      pipeline entry point (python -m secfix)
├── tests/
│   ├── test_agent.py               adapters + fixers (unit)
│   ├── test_scanner_clients.py     LIVE API clients vs mock vendor servers
│   ├── test_pipeline_e2e.py        full pipeline vs mock GitHub + bare git remote
│   └── test_hard_cases.py          hard/complex scan stress test
└── .github/
    ├── workflows/security-fix.yml  scan → fix → PR (auto-selects live vs file)
    ├── workflows/ci.yml            runs all test suites on push/PR
    └── actions/secfix/action.yml   reusable composite action
```

---

## 2. The pipeline, stage by stage

```text
collect findings ─▶ normalize ─▶ policy filter ─▶ fix ─▶ validate ─▶ publish
   (live API or       (common      (severity)   (SCA +     (tests +    (PR / MR)
    JSON file)         Finding)                  SAST)      re-check)
```

Each stage is a separate module so it can be tested and swapped independently.

---

## 3. The common `Finding` model — `secfix/models.py`

Every scanner is normalized into one dataclass so all downstream code is
scanner-agnostic.

| Field | Meaning |
| --- | --- |
| `scanner` | `blackduck` \| `fortify` |
| `type` | `dependency_vuln` \| `code_vuln` |
| `severity` | `critical` \| `high` \| `medium` \| `low` |
| `title` | human label |
| `cve` | CVE id (SCA) |
| `category` | SAST category, e.g. `SQL Injection` |
| `file`, `line` | code location (SAST) |
| `component`, `current_version`, `fixed_version` | dependency info (SCA) |
| `raw_ref` | scanner-native id (origin id / issueInstanceId) |

**Fingerprint** — a stable id used for correlation/de-dup, deliberately
excluding volatile fields (version, line number) so the *same* underlying
problem always hashes the same:

```python
key = "|".join([scanner, type, cve, category, component, file])
fingerprint = "sha256:" + sha256(key)[:16]
```

**Severity ordering** — `severity_rank()` sorts critical→low so the worst issues
are handled first.

---

## 4. Scanner adapters — `secfix/normalize.py`

Adapters convert raw vendor JSON into `Finding`s. They are the *only* place you
touch to support a new scanner or format.

### Black Duck (`normalize_blackduck`)
Input (one item of `…/vulnerable-bom-components`):
```json
{ "componentName": "PyYAML", "componentVersionName": "5.3",
  "vulnerabilityWithRemediation": {
    "vulnerabilityName": "CVE-2020-14343", "severity": "CRITICAL",
    "solution": "Upgrade to 5.4 or later" } }
```
→ `Finding(scanner="blackduck", type="dependency_vuln", severity="critical",
cve="CVE-2020-14343", component="PyYAML", current_version="5.3",
fixed_version="5.4")`.

The `fixed_version` is parsed from the free-text `solution` with a version regex
(`Upgrade to 5.4 or later` → `5.4`; `No fix available` → `None`).

### Fortify (`normalize_fortify`)
Input (one item of `…/issues`):
```json
{ "issueInstanceId": "F0RT1FY-SQLI", "category": "SQL Injection",
  "friority": "Critical", "fullFileName": "sample_app/db.py", "lineNumber": 13 }
```
→ `Finding(scanner="fortify", type="code_vuln", severity="critical",
category="SQL Injection", file="sample_app/db.py", line=13)`.

---

## 5. Live scanner clients — `secfix/scanners/`

When you provide a base URL, secfix pulls findings straight from the real vendor
REST APIs instead of a file. Both clients use only the standard library.

### Black Duck — `blackduck_client.py`
Real auth + resource navigation:
1. `POST /api/tokens/authenticate` with `Authorization: token <api-token>` → `bearerToken`.
2. `GET /api/projects?q=name:<project>` → follow `_meta.href`.
3. `GET <projectHref>/versions?q=versionName:<version>` → follow `_meta.href`.
4. `GET <versionHref>/vulnerable-bom-components` → `{"items":[…]}`.

### Fortify SSC — `fortify_client.py`
1. `GET /api/v1/projectVersions?q=name:<version>` with `Authorization: FortifyToken <token>` → resolve app+version to id.
2. `GET /api/v1/projectVersions/<id>/issues` → `{"data":[…]}`.

Both return the **same dict shape** as the JSON files, so `normalize_*` handles
them unchanged. `gather.collect_findings(args)` decides live-vs-file per scanner:
live when `--blackduck-url`/`$BD_URL` (resp. `--fortify-url`/`$SSC_URL`) is set,
otherwise it reads the `--blackduck`/`--fortify` file.

> These clients are covered by [tests/test_scanner_clients.py](../tests/test_scanner_clients.py),
> which stands up **mock servers replicating the real vendor auth + endpoints**
> and asserts the whole live pipeline (fetch → fix → validate).

---

## 6. Fix strategies

### 6.1 SCA — dependency bumper (`fixers/deps.py`)
Parses `requirements.txt`, matches vulnerable components (name-normalized:
`PyYAML` == `pyyaml`), and rewrites `name==version` → the fixed version. All
dependency bumps become **one** patch (one coherent diff for the reviewer).
Untouched lines are preserved byte-for-byte.

- **Multiple CVEs on one component** → the **highest** fixed version wins
  (`_ver_key` numeric sort). Example from the hard test: PyYAML has CVE-2020-1747
  (→5.3.1) and CVE-2020-14343 (→5.4); secfix bumps to **5.4**.
- **Transitive / not-in-manifest** components → **escalated** (can't bump a line
  that isn't there).
- **No fixed version** available → **escalated**.

Before / after:
```diff
- PyYAML==5.3
- requests==2.19.1
+ PyYAML==5.4
+ requests==2.20.0
```

### 6.2 SAST — deterministic rules (`fixers/rules.py`)
Trusted, behaviour-preserving templates for well-understood categories:

| Category | Transformation | Example |
| --- | --- | --- |
| Weak Cryptographic Hash | `hashlib.md5/sha1(` → `hashlib.sha256(` | `hashlib.md5(x)` → `hashlib.sha256(x)` |
| Insecure Deserialization | `yaml.load(x, Loader=…)` → `yaml.safe_load(x)` | drops the unsafe `Loader=` |
| Command Injection | concat command + `shell=True` → arg list, no shell | `subprocess.call(cmd, shell=True)` → `subprocess.call(cmd)` with `cmd=[…]` |
| SQL Injection | `"… '" + v + "'"` → `"… ?", (v,)` | parameterized query |

Each rule also has a **residue pattern** used to verify the vulnerability is
actually gone after the change.

### 6.3 SAST — AI provider (`fixers/sast.py`, optional)
For categories the rules don't cover, an optional **Vertex AI (Gemini)** provider
proposes a minimal patch. It is enabled only when `SECFIX_LLM_PROVIDER=vertex`
plus Google credentials are present. **Its output is never trusted blindly** —
it must still clear the residue check and pass validation, else it's discarded.

### 6.4 Orchestrator (`fixers/code.py`)
Per code finding: try **AI first** (if enabled) → if it verifies, use it; else
try the **rule engine** → if it verifies, use it; else **return None →
escalate**. This is the core safety property: *no unverified change reaches a
PR.*

---

## 7. Hard cases & escalation (tested)

The agent is designed to **fix only what it can prove and escalate the rest**.
Real output from [tests/test_hard_cases.py](../tests/test_hard_cases.py) —
**13 findings → 4 fixed, 9 escalated**:

```text
secfix v0.1.0: 13 findings, 13 within severities ['critical', 'high', 'medium']
  [deps] PyYAML 5.3 -> 5.4 (CVE-2020-14343)          ← highest of two CVEs
  [deps] requests 2.19.1 -> 2.20.0 (CVE-2018-18074)
  [escalate] legacy-cipher CVE-2021-99999 (no fixed version)
  [escalate] certifi CVE-2022-23491 (not a direct dependency)   ← transitive
  [rule] fixed Command Injection in app.py
  [escalate] Insecure Deserialization in app.py (no verified fix)   ← pickle
  [escalate] SQL Injection in app.py (no verified fix)             ← f-string form
  [escalate] Dynamic Code Evaluation in app.py (no verified fix)   ← eval
  [rule] fixed Weak Cryptographic Hash in app.py
  [escalate] Path Manipulation in app.py (no verified fix)
  [escalate] XML External Entity Injection in app.py (no verified fix)
  [escalate] Hardcoded Password in app.py (no verified fix)
OK  PyYAML CVE-2020-14343   OK  requests CVE-2018-18074
OK  Command Injection (app.py:23)   OK  Weak Cryptographic Hash (app.py:17)
```

The generated PR body lists both sections:

```markdown
### Fixed
- CVE-2020-14343 (critical) — bump PyYAML 5.3 → 5.4 (Black Duck)
- CVE-2018-18074 (high)     — bump requests 2.19.1 → 2.20.0 (Black Duck)
- Command Injection (critical) in app.py (Fortify · provider: rule)
- Weak Cryptographic Hash (high) in app.py (Fortify · provider: rule)

### ⚠️ Needs human attention (not auto-fixed)
- legacy-cipher CVE-2021-99999 (critical)   - certifi CVE-2022-23491 (high)
- Insecure Deserialization (critical)       - SQL Injection (critical)
- Dynamic Code Evaluation (critical)        - Path Manipulation (high)
- XML External Entity Injection (high)      - Hardcoded Password (high)
```

> Why escalate these? XXE/SSRF/pickle/eval/path-traversal/secret and f-string
> SQLi require context-specific rewrites (canonicalization, allow-lists, safe
> loaders, secret rotation). Guessing risks a broken or falsely-"fixed" change.
> With the Vertex AI provider enabled, several of these become AI-fixed — but
> still only if the patch validates.

---

## 8. Validation — `secfix/validate.py`

No patch reaches a PR without passing validation:
1. **Tests** — runs `--test-cmd` (e.g. `python -m unittest discover -s tests`);
   failure aborts with exit code 3 (no PR).
2. **Presence check (SCA)** — confirms `name==fixed_version` is now pinned.
3. **Residue check (SAST)** — confirms the vulnerability pattern is gone.

The `sample_app` behaviour tests prove fixes are **behaviour-preserving**: all 4
pass *after* the SQL/hash/yaml/command fixes are applied.

---

## 9. Publishing — `git_ops.py`, `github_pr.py`, `gitlab_mr.py`

- `git_ops.py` — shared `create_branch_and_commit`, `push` (via git CLI).
- `github_pr.py` — `POST /repos/:owner/:repo/pulls` + labels, honours
  `GITHUB_API_URL` (GitHub Enterprise / testing).
- `gitlab_mr.py` — `POST /projects/:id/merge_requests` on the GitLab API.

Selection: `--provider auto` picks GitLab when `GITLAB_CI`/`CI_SERVER_URL` is
set, else GitHub. Branch is `secfix/auto-<timestamp>`; labels `security`,
`automated`. The PR/MR body is the generated markdown from §7.

---

## 10. CLI reference — `python -m secfix`

```text
--root DIR                 repo root to operate on (default ".")

# scan source — FILE mode
--blackduck FILE           Black Duck report JSON (omit to skip SCA)
--fortify FILE             Fortify report JSON (omit to skip SAST)
# scan source — LIVE mode
--blackduck-url URL        Black Duck base URL   (token via $BD_API_TOKEN)
--blackduck-project NAME   Black Duck project name
--blackduck-version NAME   Black Duck version (default main)
--fortify-url URL          Fortify SSC base URL  (token via $FORTIFY_TOKEN)
--fortify-app NAME         Fortify application name
--fortify-version NAME     Fortify version (default main)

--req PATH                 requirements file, relative to root
--severities LIST          severities to auto-fix (default critical,high,medium)
--test-cmd "…"             validation command (must exit 0)

# publishing
--base BRANCH              PR/MR target branch (default main)
--branch NAME              head/source branch (default auto)
--provider auto|github|gitlab
--repo owner/name          GitHub repo (default $GITHUB_REPOSITORY)
--project ID|group/name    GitLab project (default $CI_PROJECT_ID)
--gitlab-url URL           GitLab base URL (default $CI_SERVER_URL)
--open-pr                  commit, push and open the PR/MR
--pr-body-out FILE         write the PR/MR body markdown
--fail-on-findings         exit 2 if actionable findings were present
```

### Example — file mode, report only (no PR)
```bash
py -m secfix --root . \
  --blackduck scan_reports/blackduck.json \
  --fortify   scan_reports/fortify.json \
  --req sample_app/requirements.txt \
  --severities critical,high \
  --test-cmd "py -m unittest discover -s sample_app/tests" \
  --pr-body-out pr-body.md
```

### Example — live mode + open a GitHub PR
```bash
export BD_API_TOKEN=…  FORTIFY_TOKEN=…  GITHUB_TOKEN=…
python -m secfix --root . \
  --blackduck-url https://blackduck.example.com --blackduck-project my-svc \
  --fortify-url   https://ssc.example.com       --fortify-app     my-svc \
  --req requirements.txt --severities critical,high \
  --test-cmd "python -m pytest -q" \
  --repo my-org/my-svc --open-pr
```

---

## 11. Environment variables

| Var | Purpose |
| --- | --- |
| `GITHUB_TOKEN` | required for `--open-pr` on GitHub |
| `GITHUB_API_URL` | GitHub REST base (Enterprise/testing; default api.github.com) |
| `GITLAB_TOKEN`, `CI_PROJECT_ID`, `CI_SERVER_URL`, `CI_API_V4_URL` | GitLab MR publishing |
| `BD_URL`, `BD_API_TOKEN` | live Black Duck |
| `SSC_URL`, `FORTIFY_TOKEN` | live Fortify |
| `SECFIX_LLM_PROVIDER=vertex`, `GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_CLOUD_PROJECT`, `VERTEX_LOCATION`, `VERTEX_MODEL` | optional AI-assisted SAST fixes |

Secrets belong **only** in your CI secret store — never in code or the YAML.

---

## 12. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success (fixes applied / PR opened, or nothing actionable) |
| 2 | `--fail-on-findings` set and actionable findings existed |
| 3 | validation failed (tests did not pass) — no PR |
| 4 | `--open-pr` requested but publisher credentials/target missing |

---

## 13. Testing

| Suite | What it proves |
| --- | --- |
| `tests/test_agent.py` | adapters + each SAST rule + dep bumper |
| `tests/test_scanner_clients.py` | live Black Duck/Fortify clients vs mock vendor APIs + full live pipeline |
| `tests/test_pipeline_e2e.py` | end-to-end: fix → git branch/commit/push (bare remote) → PR POST (mock GitHub) |
| `tests/test_hard_cases.py` | hard/complex scans: fix-what-you-can, escalate-the-rest |
| `sample_app/tests/test_app.py` | fixes are behaviour-preserving |

Run everything:
```bash
py -m unittest discover -s tests            # 13 tests
py -m unittest discover -s sample_app/tests # 4 tests
```
All run offline. `ci.yml` runs them on every push/PR.

---

## 14. Security & safety guardrails

- **Propose, don't auto-merge** — opens a branch + PR/MR; humans merge.
- **Validation gate** — no PR without passing tests + residue/presence re-check.
- **Escalate, never guess** — unverifiable fixes are listed for humans.
- **Least privilege** — read-only scanner tokens; a bot token that can push
  branches + open PRs but not merge protected branches.
- **Secrets only in CI store**; AI patches validated, not trusted.
- **No loops** — the workflow skips its own `secfix/*` branches and ignores
  docs/test/workflow-only pushes.

---

## 15. Extending

- **New ecosystem (npm, Maven, Go…):** add a bumper beside `deps.py` that
  rewrites that manifest and register it in `cli.py`.
- **New scanner (Snyk, Trivy, Semgrep…):** add `normalize_<tool>()` in
  `normalize.py` returning `Finding`s (and optionally a client in `scanners/`).
- **New SAST template:** add a handler + residue pattern in `rules.py`.
- **New Git host (Bitbucket, Azure Repos):** add a publisher beside
  `github_pr.py` and a `--provider` branch in `cli.py`.

---

## 16. Known limitations

- **No cross-run de-duplication of PRs** in this CI-only version — each run opens
  a fresh PR (the fingerprint exists but there is no persistent state store).
  Mitigation: the workflow's `paths-ignore` avoids re-running on docs/test
  changes; close superseded PRs, or add a state store to correlate by
  fingerprint.
- **Rule engine is Python-specific**; other languages rely on the Vertex AI
  provider (still validated by your `--test-cmd`).
- **Dependency bumping targets `requirements.txt`**; other manifests need a
  bumper (see §15).
