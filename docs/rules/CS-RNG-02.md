# CS-RNG-02 — randomBytes length too small

| Field        | Value     |
| ------------ | --------- |
| **ID**       | CS-RNG-02 |
| **Severity** | high      |
| **Category** | RNG       |

## Why it matters

`crypto.randomBytes(n)` is cryptographically secure, but **short outputs are guessable**. For session tokens, API keys, OTPs, and similar secrets, **at least 16 bytes (128 bits)** of entropy is a common minimum. Values like `randomBytes(4)` or `randomBytes(8)` in auth paths are too small for production use.

**CS-RNG-01** flags **`Math.random()`** in auth context — the wrong RNG entirely. This rule flags **`randomBytes(n)` with n < 16** when auth naming suggests the output protects a secret.

## Bad example

```typescript
import { randomBytes } from "crypto";

export function generateSessionToken() {
	return randomBytes(8).toString("hex");
}
```

```typescript
import { randomBytes } from "crypto";

export function generateOtpCode() {
	return randomBytes(1).toString("hex");
}
```

## Good example

```typescript
import { randomBytes } from "crypto";

export function generateSessionToken() {
	return randomBytes(32).toString("hex");
}
```

```typescript
import { randomBytes } from "crypto";

export function generateApiKey() {
	return randomBytes(16).toString("base64url");
}
```

## What CipherSins checks

- **Tracked randomBytes calls:** `randomBytes` from Node **`crypto`** / **`node:crypto`** (import-aware bindings via **`crypto-cipher-bindings`**).
- **Length argument:** 1st argument to `randomBytes`.
- **Insufficient length:** numeric literal **< 16**, or same-file identifier bound to a numeric literal **< 16**.
- **Auth context:** function/method name, parameter, or local binding in the enclosing scope chain matches auth-material naming (`token`, `session`, `otp`, `secret`, …) — same heuristic as CS-RNG-01 via **`enclosing-function`**.
- **Same-file scope only (v1).**

## Relationship to CS-RNG-01

| Call site in auth-named function    | CS-RNG-01 (`Math.random`) | CS-RNG-02 (`randomBytes` too short) |
| ----------------------------------- | ------------------------- | ----------------------------------- |
| `Math.random()`                     | **Flagged**               | **Not flagged**                     |
| `randomBytes(4)`                    | **Not flagged**           | **Flagged**                         |
| `randomBytes(16)`                   | **Not flagged**           | **Not flagged**                     |
| `Math.random()` + `randomBytes(4)`  | **Flagged**               | **Flagged**                         |
| `randomBytes(4)` in `renderChart()` | **Not flagged**           | **Not flagged** (no auth context)   |

Both rules can fire in the same auth function when **`Math.random()`** and short **`randomBytes()`** appear together.

## False positives and limits

| Scenario                                       | Behavior                                           |
| ---------------------------------------------- | -------------------------------------------------- |
| `randomBytes(16)` in `generateToken()`         | **Not flagged** — at minimum length                |
| `randomBytes(15)` in `generateToken()`         | **Flagged** — below 16 bytes                       |
| `randomBytes(4)` in `pickColor()`              | **Not flagged** — no auth naming                   |
| `randomBytes(lengthVar)` in auth function      | **Not flagged in v1** unless literal-resolved      |
| `crypto.randomUUID()`                          | **Not flagged** — not randomBytes                  |
| Short randomBytes in `*.test.ts` / `*.spec.ts` | **Excluded by default scan globs**, not rule logic |

## Fix

Use **at least 16 bytes** (prefer **32 bytes** for long-lived tokens and keys):

```typescript
return randomBytes(32).toString("hex");
```

Replace any remaining **`Math.random()`** auth usage — see **[CS-RNG-01](./CS-RNG-01.md)**.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-RNG-02
return randomBytes(8).toString("hex");
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **Node `crypto` / `node:crypto`:** `randomBytes` with import-aware bindings via **`crypto-cipher-bindings`** and **`random-bytes-length`**.

## Limitations

See [False positives and limits](#false-positives-and-limits). Length from config files, cross-file constants, or non-literal expressions is not resolved in v1.3.

## Source

[`packages/ciphersins/src/rules/cs-rng-02.ts`](https://github.com/01laky/CipherSins/blob/main/packages/ciphersins/src/rules/cs-rng-02.ts)

## References

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- Related: [CS-RNG-01](./CS-RNG-01.md) — Math.random in auth context
