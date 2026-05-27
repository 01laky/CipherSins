# CipherSins

Static scanner for JWT, timing, and weak crypto footguns in Node/TS app code.

**Tagline:** _gitleaks for bad crypto API usage_ — not secrets in strings, but footguns in application code.

```bash
pnpm exec ciphersins scan ./src
```

See [`docs/proposal.MD`](./docs/proposal.MD) for the full product spec.

## Status (v0.3.0)

- pnpm monorepo: `@ciphersins/core` + `ciphersins` CLI
- TypeScript compiler API parsing with default include/exclude globs
- **CS-JWT-01** — flags `jsonwebtoken` decode without verify in the same file
- Vitest scaffold suite **CS-S01–CS-S22**, edge-case suite **CS-S23–CS-S46**, rule suite **CS-JWT-01-01–24**

### Example

```bash
pnpm exec ciphersins scan fixtures/cs-jwt-01/bad
```

```text
fixtures/cs-jwt-01/bad/default-import-decode-only.ts:4:9  CS-JWT-01  high
  jwt.decode() used without jwt.verify() in the same file.
  https://github.com/01laky/ciphersins/blob/main/docs/rules/CS-JWT-01.md
```

## Rules (MVP)

| ID                                     | Severity | Title                       | Status      |
| -------------------------------------- | -------- | --------------------------- | ----------- |
| [CS-JWT-01](./docs/rules/CS-JWT-01.md) | high     | JWT decode without verify   | implemented |
| CS-JWT-02                              | high     | Verify without algorithms   | planned     |
| CS-JWT-03                              | critical | Algorithm none / bypass     | planned     |
| CS-JWT-04                              | medium   | Missing exp validation      | planned     |
| CS-CMP-01                              | high     | Timing-unsafe compare       | planned     |
| CS-RNG-01                              | high     | Math.random in auth context | planned     |

Full index: [`docs/rules/README.md`](./docs/rules/README.md).

## Quick start (development)

```bash
pnpm install
./scripts/setup-githooks.sh
pnpm verify
pnpm exec ciphersins scan test/fixtures/scaffold
```

See [`docs/development.md`](./docs/development.md) for the full contributor guide.

## Documentation

| Doc                                                                            | Description                                         |
| ------------------------------------------------------------------------------ | --------------------------------------------------- |
| [`docs/proposal.MD`](./docs/proposal.MD)                                       | Product spec, MVP rules, architecture               |
| [`docs/development.md`](./docs/development.md)                                 | Local setup, commands, monorepo layout              |
| [`docs/rules/README.md`](./docs/rules/README.md)                               | Rule index and documentation                        |
| [`docs/ciphersins.config.example.json`](./docs/ciphersins.config.example.json) | Intended config schema (parser not yet implemented) |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md)                                         | Commit standards, git hooks                         |

## License

MIT — see [`LICENSE`](./LICENSE).
