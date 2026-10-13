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

Both the per-org project listing and the SBOM fetches run through the same
bounded thread pool (`--concurrency`), so wall-clock time now tracks total
project count more than org count. Rough math at ~0.4s/call (measured) and
concurrency 10: ~100 orgs/1,000 projects in well under a minute; ~1,000
orgs/10,000 projects in a few minutes; low tens of thousands of
orgs/projects starts climbing into the 10-20 minute range. That's
wall-clock time under ideal conditions — it doesn't account for how a given
tenant's actual API rate limits hold up at that request volume, which this
hasn't been stress-tested against.

- **Concurrent** SBOM fetches via a bounded thread pool (`--concurrency`)
- **Rate-limit aware** — retries on 429/5xx with backoff, honoring a
  `Retry-After` header when the server sends one
- **Resumable by default** — a project already written to disk is read back
  instead of re-fetched, so re-running the same command after a crash or
  interruption just picks up where it left off (`--force` to disregard)
- Per-project dependency trees are written as their own small HTML files
  rather than embedded in the main report, so report size stays proportional
  to project count, not to the combined size of every dependency graph in
  the Group

## Known limitation

This produces **one SBOM document per project** (optionally merged into
CSV/JSON views for reporting) — Snyk doesn't support generating a single
SBOM document that merges multiple projects' dependency graphs into one, and
this script doesn't attempt that either.
