# CS-HASH-05 — argon2 parameters too low

| Field        | Value      |
| ------------ | ---------- |
| **ID**       | CS-HASH-05 |
| **Severity** | medium     |
| **Category** | Hash       |

## Why it matters

Argon2 is a modern memory-hard password hash. OWASP recommends **timeCost ≥ 3** and **memoryCost ≥ 65,536 KiB (64 MiB)** as a baseline for interactive login. Low parameters reduce resistance to offline cracking.

**CS-HASH-03** flags low **PBKDF2** iterations; **CS-HASH-04** flags low **scrypt** cost. This rule covers **`argon2`** and **`@node-rs/argon2`** `hash` / `hashSync` calls.

## Bad example

```typescript
import argon2 from "argon2";

export async function hashPassword(password: string) {
	return argon2.hash(password, { timeCost: 2, memoryCost: 65536 });
}
```

```typescript
import { hashSync } from "@node-rs/argon2";

export function hashPassword(password: string) {
	return hashSync(password, { timeCost: 1, memoryCost: 32768 });
}
```

## Good example

```typescript
import argon2 from "argon2";

export async function hashPassword(password: string) {
	return argon2.hash(password, { timeCost: 3, memoryCost: 65536 });
}
```

```typescript
import bcrypt from "bcrypt";

export async function hashPassword(password: string) {
	return bcrypt.hash(password, 12);
}
```

## What CipherSins checks

- **Tracked argon2 calls:** `hash` and `hashSync` from **`argon2`** or **`@node-rs/argon2`** (default/named import, `require`, destructured require).
- **Options object:** 2nd argument to `hash`, or 2nd/3rd argument to `hashSync` when it is an object literal.
- **Weak parameter:** `timeCost` < **3** or `memoryCost` < **65,536** (numeric literal or same-file identifier bound to a numeric literal).
- **`memoryCost` units:** values are interpreted as **KiB** (kibibytes), matching the argon2 library convention — **65,536 KiB = 64 MiB**.
- **Password context:** function/method/parameter/binding names match password-related naming (same heuristic as CS-HASH-01/02/03/04).
- **Same-file scope only (v1).**

## Relationship to CS-HASH-03 and CS-HASH-04

| Call site                                              | CS-HASH-03 (PBKDF2) | CS-HASH-04 (scrypt) | CS-HASH-05 (argon2) |
| ------------------------------------------------------ | ------------------- | ------------------- | ------------------- |
| `pbkdf2Sync(pwd, salt, 1000, 32, "sha256")`            | **Flagged**         | **Not flagged**     | **Not flagged**     |
| `scryptSync(pwd, salt, 64, { cost: 8192 })`            | **Not flagged**     | **Flagged**         | **Not flagged**     |
| `argon2.hash(pwd, { timeCost: 2 })`                    | **Not flagged**     | **Not flagged**     | **Flagged**         |
| `argon2.hash(pwd, { timeCost: 3, memoryCost: 65536 })` | **Not flagged**     | **Not flagged**     | **Not flagged**     |
| `argon2.hash(apiKey, { timeCost: 1 })`                 | **Not flagged**     | **Not flagged**     | **Not flagged**     |

Each KDF rule applies only to its own API — no double findings across HASH-03/04/05.

## False positives and limits

| Scenario                                                    | Behavior                                                              |
| ----------------------------------------------------------- | --------------------------------------------------------------------- |
| `argon2.hash(password, { timeCost: 3, memoryCost: 65536 })` | **Not flagged** — at minimum thresholds                               |
| `argon2.hash(password, { timeCost: 2 })`                    | **Flagged** — timeCost below 3                                        |
| `argon2.hash(password, { memoryCost: 32768 })`              | **Flagged** — memoryCost below 65,536 KiB                             |
| `argon2.hash(password)` (no options)                        | **Not flagged** — library defaults not evaluated                      |
| `argon2.hash(password, { timeCost: costVar })`              | **Not flagged in v1** unless `costVar` is a same-file numeric literal |
| `argon2.hash(apiKey, { timeCost: 1 })`                      | **Not flagged** — no password context                                 |
| `bcrypt.hash(password, 12)`                                 | **Not flagged** — not argon2                                          |
| Low argon2 params in `*.test.ts` / `*.spec.ts`              | **Excluded by default scan globs**, not rule logic                    |

## Fix

Raise argon2 parameters to **timeCost ≥ 3** and **memoryCost ≥ 65,536 KiB** (prefer higher for high-value accounts), or use **bcrypt** (cost ≥ 12) with appropriate cost tuning.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-HASH-05
return argon2.hash(password, { timeCost: 2, memoryCost: 65536 });
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **`argon2`** and **`@node-rs/argon2`:** `hash`, `hashSync` with import-aware bindings via **`argon2-bindings`** and **`argon2-params`**.

## Limitations

See [False positives and limits](#false-positives-and-limits). Parameters from config files, cross-file constants, or non-literal expressions are not resolved in v1.3. Library default parameters (when no options object is passed) are not flagged.

## Source

[`packages/ciphersins/src/rules/cs-hash-05.ts`](https://github.com/01laky/CipherSins/blob/main/packages/ciphersins/src/rules/cs-hash-05.ts)

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- Related: [CS-HASH-03](./CS-HASH-03.md) — PBKDF2 iterations too low
- Related: [CS-HASH-04](./CS-HASH-04.md) — scrypt cost too low
