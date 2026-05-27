# CLI reference

Command-line interface for `ciphersins` (`packages/cli`). Product overview: [about.md](./about.md).

## Commands

```bash
pnpm exec ciphersins scan [path] [options]
pnpm exec ciphersins scan --help
pnpm exec ciphersins --help
pnpm exec ciphersins --version
```

| Command           | Description                                            |
| ----------------- | ------------------------------------------------------ |
| `scan [path]`     | Scan TypeScript/JavaScript files for crypto API misuse |
| `scan --help`     | Scan-specific flags, exit codes, and examples          |
| `--help`, `-h`    | Top-level usage (command list)                         |
| `--version`, `-v` | Print package version (**0.9.0**)                      |

When `path` is omitted, the scan root is `./src` if it exists, otherwise `.`. Multiple paths are supported: `ciphersins scan dir1 dir2`.

## Scan flags

| Flag                | Type                                                | Default       | Description                                                                  |
| ------------------- | --------------------------------------------------- | ------------- | ---------------------------------------------------------------------------- |
| `--format <fmt>`    | `pretty` \| `json` \| `sarif`                       | `pretty`      | Output format                                                                |
| `--fail-on <level>` | `none` \| `low` \| `medium` \| `high` \| `critical` | _(absent)_    | Exit **1** when findings at or above level exist; **`none`** disables gating |
| `--output <file>`   | string                                              | stdout        | Write formatted output to file (parent dirs created)                         |
| `--config <path>`   | string                                              | auto-discover | Load JSON config from explicit path                                          |
| `--no-config`       | boolean                                             | false         | Skip `ciphersins.config.json` discovery                                      |
| `--quiet`           | boolean                                             | false         | Suppress stdout (still writes `--output` file; stderr warnings remain)       |

CamelCase alias: `--failOn` is accepted as `--fail-on`.

## Output formats

### Pretty (default)

Each finding is printed as:

```text
relative/path.ts:line:column  CS-JWT-01  high
  jwt.decode() used without jwt.verify() in the same file.
  https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-JWT-01.md
```

When there are no findings: `No findings.`

### JSON

Machine-readable document with `schemaVersion: 1`, severity summary, relative paths, and sorted findings. Zero findings still emit full JSON (`findings: []`), not the pretty string.

```json
{
	"schemaVersion": 1,
	"version": "0.9.0",
	"tool": "ciphersins",
	"summary": { "low": 0, "medium": 0, "high": 0, "critical": 1, "total": 1 },
	"scannedFiles": ["src/auth.ts"],
	"skippedPaths": [],
	"findings": []
}
```

Programmatic equivalent: `formatJson()` from `@ciphersins/core`.

### SARIF 2.1.0

GitHub Code Scanning–compatible SARIF with full `tool.driver.rules` catalog (all 8 MVP rules), `partialFingerprints`, and `originalUriBaseIds.%WORKINGDIR%`.

Programmatic equivalent: `formatSarif()` from `@ciphersins/core`.

When `--output` is set, formatted output is written **only** to the file (stdout stays empty unless stderr warnings or fail summary apply).

## Exit codes

| Code  | Meaning                                                                          |
| ----- | -------------------------------------------------------------------------------- |
| **0** | Scan completed; no findings at/above `--fail-on` threshold (or threshold absent) |
| **1** | Scan completed; one or more findings at/above `--fail-on` threshold              |
| **2** | Unknown command, invalid flags, config error, or scan failure (parse/I/O)        |

**Backward compatibility:** scans without `--fail-on` always exit **0** on success, even when findings are present.

On exit **1**, a one-line stderr summary is printed (even with `--quiet`):

```text
error: 3 finding(s) at or above high (critical: 1, high: 2)
```

Missing scan paths emit a **warning** on stderr and are skipped.

## Config file (`ciphersins.config.json`)

Optional JSON in the process working directory (or via `--config`). **Do not** commit a root config with `failOn` to the monorepo — tests and smoke-cli rely on `--no-config` or absence of config.

```json
{
	"include": ["src/**/*.{ts,tsx,js,jsx}"],
	"exclude": ["**/*.test.ts", "**/dist/**"],
	"failOn": "high"
}
```

| Key       | Type       | Maps to                                  |
| --------- | ---------- | ---------------------------------------- |
| `include` | `string[]` | Scan include globs                       |
| `exclude` | `string[]` | Scan exclude globs                       |
| `failOn`  | severity   | Default `--fail-on` when CLI flag absent |

CLI flags override config. `--fail-on none` disables config `failOn` for that run.

Per-rule severity overrides (`rules.CS-JWT-02: "warn"`) are **not** implemented in v0.9.0 — planned for v1.0.0.

## GitHub Actions example

```yaml
- name: CipherSins scan
  run: |
    npm run build
    node packages/cli/dist/cli.js scan ./src \
      --format sarif \
      --output ciphersins.sarif \
      --fail-on high
  continue-on-error: false

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ciphersins.sarif
```

## Examples

```bash
pnpm exec ciphersins scan ./src
pnpm exec ciphersins scan --format json --fail-on high
pnpm exec ciphersins scan --format sarif --output results.sarif --fail-on high
pnpm exec ciphersins scan --fail-on none
pnpm exec ciphersins scan --no-config fixtures/cs-jwt-03/bad
pnpm exec ciphersins scan fixtures/cs-jwt-01/bad fixtures/cs-jwt-02/bad
```

Severity levels in v0.9.0: **critical** (JWT-03), **high** (JWT-01/02, CMP, RNG, HASH-01), **medium** (JWT-04, HASH-02).
