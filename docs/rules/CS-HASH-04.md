# CS-HASH-04 — scrypt cost factor too low

| Field        | Value      |
| ------------ | ---------- |
| **ID**       | CS-HASH-04 |
| **Severity** | medium     |
| **Category** | Hash       |

## Why it matters

scrypt adds memory-hardness on top of iteration count. OWASP recommends **N (cost) ≥ 2¹⁴ (16,384)**, **r (blockSize) ≥ 8**, and **p (parallelization) ≥ 1** for password hashing. Low parameters make offline cracking practical even when the underlying digest is strong.

**CS-HASH-03** flags low **PBKDF2** iterations; **CS-HASH-05** flags low **argon2** parameters. This rule covers **scrypt** / **scryptSync** from Node `crypto`.

## Bad example

```typescript
import { scryptSync } from "crypto";

export function hashPassword(password: string, salt: Buffer) {
	return scryptSync(password, salt, 64, { cost: 8192 });
}
```

```typescript
import { scrypt } from "crypto";

export function hashPassword(
	password: string,
	salt: Buffer,
	cb: (err: Error | null, key: Buffer) => void,
) {
	scrypt(password, salt, 64, { cost: 8192, blockSize: 4 }, cb);
}
```

## Good example

```typescript
import { scryptSync } from "crypto";

export function hashPassword(password: string, salt: Buffer) {
	return scryptSync(password, salt, 64, {
		cost: 16384,
		blockSize: 8,
		parallelization: 1,
	});
}
```

```typescript
import bcrypt from "bcrypt";

export async function hashPassword(password: string) {
	return bcrypt.hash(password, 12);
}
```

## What CipherSins checks

- **Tracked scrypt calls:** `scrypt` and `scryptSync` from Node **`crypto`** / **`node:crypto`** (import-aware bindings via **`hash-bindings`**).
- **Explicit options object:** 4th argument to `scryptSync`, or 4th argument to async `scrypt` when a 5th callback argument is present.
- **Weak parameter:** any of `cost` < **16,384**, `blockSize` < **8**, or `parallelization` < **1** (numeric literal or same-file identifier bound to a numeric literal).
- **Password context:** function/method/parameter/binding names match password-related naming (same heuristic as CS-HASH-01/02/03).
- **Same-file scope only (v1).**

## Relationship to CS-HASH-03 and CS-HASH-05

| Call site                                      | CS-HASH-03 (PBKDF2) | CS-HASH-04 (scrypt) | CS-HASH-05 (argon2) |
| ---------------------------------------------- | ------------------- | ------------------- | ------------------- |
| `pbkdf2Sync(pwd, salt, 1000, 32, "sha256")`    | **Flagged**         | **Not flagged**     | **Not flagged**     |
| `scryptSync(pwd, salt, 64, { cost: 8192 })`    | **Not flagged**     | **Flagged**         | **Not flagged**     |
| `argon2.hash(pwd, { timeCost: 2 })`            | **Not flagged**     | **Not flagged**     | **Flagged**         |
| `scryptSync(pwd, salt, 64)` (no options)       | **Not flagged**     | **Not flagged**     | **Not flagged**     |
| `scryptSync(apiKey, salt, 64, { cost: 8192 })` | **Not flagged**     | **Not flagged**     | **Not flagged**     |

Each KDF rule applies only to its own API — no double findings across HASH-03/04/05.

## False positives and limits

| Scenario                                                        | Behavior                                                              |
| --------------------------------------------------------------- | --------------------------------------------------------------------- |
| `scryptSync(password, salt, 64, { cost: 16384, blockSize: 8 })` | **Not flagged** — at minimum thresholds                               |
| `scryptSync(password, salt, 64, { cost: 8192 })`                | **Flagged** — cost below 16,384                                       |
| `scryptSync(password, salt, 64)` (no options arg)               | **Not flagged** — defaults not evaluated                              |
| `scrypt(password, salt, 64, cb)` (4 args, callback only)        | **Not flagged** — no explicit options object                          |
| `scryptSync(password, salt, 64, { cost: costVar })`             | **Not flagged in v1** unless `costVar` is a same-file numeric literal |
| `scryptSync(apiKey, salt, 64, { cost: 8192 })`                  | **Not flagged** — no password context                                 |
| `bcrypt.hash(password, 12)`                                     | **Not flagged** — not scrypt                                          |
| Low scrypt params in `*.test.ts` / `*.spec.ts`                  | **Excluded by default scan globs**, not rule logic                    |

## Fix

Raise scrypt parameters to **cost ≥ 16,384**, **blockSize ≥ 8**, **parallelization ≥ 1** (prefer higher where latency allows), or migrate to **bcrypt** (cost ≥ 12) or **argon2**.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-HASH-04
return scryptSync(password, salt, 64, { cost: 8192 });
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **Node `crypto` / `node:crypto`:** `scrypt`, `scryptSync` with import-aware bindings via **`hash-bindings`** and **`scrypt-cost`**.

## Limitations

See [False positives and limits](#false-positives-and-limits). Parameters from config files, cross-file constants, or non-literal expressions are not resolved in v1.3. Default Node scrypt parameters (when no options object is passed) are not flagged.

## Source

[`packages/ciphersins/src/rules/cs-hash-04.ts`](https://github.com/01laky/CipherSins/blob/main/packages/ciphersins/src/rules/cs-hash-04.ts)

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- Related: [CS-HASH-03](./CS-HASH-03.md) — PBKDF2 iterations too low
- Related: [CS-HASH-05](./CS-HASH-05.md) — argon2 parameters too low
