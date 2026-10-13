# Group-level SBOM generator for Snyk

Not an officially supported Snyk tool — example/reference code.

Snyk's SBOM generation is natively project-scoped only (no native Group-level
export, in the API or the Web UI). This script closes that gap by looping:

**List all Orgs in a Group → List all Projects per Org → generate an SBOM for
each eligible Project.**

Modeled on an existing org-level SBOM-generation pattern, extended with the
outer Group-level loop, and rewritten against Snyk's REST API using only the
Python standard library (no `pysnyk` / `requests` dependency).

## Usage

```bash
export SNYK_API_TOKEN=<your token>
python3 group_sbom_generator.py --groupId <GROUP_ID> [options]
```

| Flag | Default | Description |
|---|---|---|
| `--format, -f` | `cyclonedx1.4+json` | SBOM format (CycloneDX 1.4–1.6, or SPDX 2.3) |
| `--outputDir, -d` | `sboms` | Local output directory |
| `--dryRun` | off | List what would be processed, no API calls to the SBOM endpoint |
| `--report` | off | Also build an aggregate report |
| `--reportFormat` | `html` | Comma-separated: `html`, `json`, `csv` — any combination |
| `--concurrency, -c` | `8` | Parallel workers for SBOM fetches |
| `--force` | off | Regenerate every SBOM even if already on disk (default resumes) |

**Example — produce just a CSV report:**

```bash
python3 group_sbom_generator.py --groupId <GROUP_ID> --report --reportFormat csv
```

Swap `csv` for `json` or `html`, or combine them, e.g. `--reportFormat html,json,csv`.

## What it writes

- One SBOM file per project: `<outputDir>/<org>/<project>__<id>.<format>`
- `report.html` — dashboard (ecosystem breakdown, most-shared components,
  per-org summary, missing-version flags, errors) plus a link to each
  project's own dependency-tree page under `<outputDir>/trees/<org>/`
- `report.json` — the same aggregate analytics, plus the full flat
  component list
- `report.csv` — flattened bill of materials, one row per
  `(org, project, component, version, purl, ecosystem)`

## Scale notes

Handles large Groups efficiently: concurrent fetching, automatic retry on
rate limits, and resumable if interrupted (safe to just re-run). Report
size stays manageable regardless of how many projects are scanned.

## Known limitation

This produces **one SBOM document per project** (optionally merged into
CSV/JSON views for reporting) — Snyk doesn't support generating a single
SBOM document that merges multiple projects' dependency graphs into one, and
this script doesn't attempt that either.
