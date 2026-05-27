# CI workflow fixture

Minimal scan root simulating a GitHub Actions job: `ciphersins.config.json` sets `failOn: high`, and `src/bad-jwt-decode.ts` triggers CS-JWT-01.

Used by **CS-CLI-60** in `test/cli/ci-workflow.test.ts`.
