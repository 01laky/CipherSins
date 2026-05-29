# CS-JWT-06 — JWT sign with noTimestamp

| Field        | Value     |
| ------------ | --------- |
| **ID**       | CS-JWT-06 |
| **Severity** | medium    |
| **Category** | JWT       |

## Why it matters

The jsonwebtoken **`noTimestamp: true`** option omits the default **`iat` (issued-at)** claim. Without a compensating **`expiresIn`** or payload **`exp`**, the token has no time bounds at all — neither issuance time nor expiration. This makes replay detection and rotation harder.

**CS-JWT-05** flags any **`jwt.sign()`** missing expiry. **CS-JWT-06** adds a targeted finding when **`noTimestamp: true`** is set explicitly without compensating expiry.

## Bad example

```typescript
import jwt from "jsonwebtoken";

export function issueToken(payload: object, secret: string) {
	return jwt.sign(payload, secret, { noTimestamp: true });
}
```

```typescript
import jwt from "jsonwebtoken";

export function issueToken(payload: object, secret: string) {
	const options = { noTimestamp: true };
	return jwt.sign(payload, secret, options);
}
```

## Good example

```typescript
import jwt from "jsonwebtoken";

export function issueToken(payload: object, secret: string) {
	return jwt.sign(payload, secret, { noTimestamp: true, expiresIn: "1h" });
}
```

```typescript
import jwt from "jsonwebtoken";

export function issueToken(payload: object, secret: string) {
	return jwt.sign(
		{ ...payload, exp: Math.floor(Date.now() / 1000) + 3600 },
		secret,
		{ noTimestamp: true },
	);
}
```

## What CipherSins checks

- **Tracked sign calls:** `jwt.sign()` from **`jsonwebtoken`** (default/named/namespace import, CommonJS `require`, destructured require).
- **`noTimestamp: true`:** literal `true` in sign options, or same-file identifier bound to `true`.
- **Missing compensating expiry:** no `expiresIn` in options and no numeric `exp` in payload (same resolution rules as CS-JWT-05).
- **Same-file scope only (v1).**

## Double finding with CS-JWT-05

| Sign call pattern                                                   | CS-JWT-05 (no expiry) | CS-JWT-06 (noTimestamp) |
| ------------------------------------------------------------------- | --------------------- | ----------------------- |
| `jwt.sign(payload, secret)`                                         | **Flagged**           | **Not flagged**         |
| `jwt.sign(payload, secret, { noTimestamp: true })`                  | **Flagged**           | **Flagged**             |
| `jwt.sign(payload, secret, { expiresIn: "1h" })`                    | **Not flagged**       | **Not flagged**         |
| `jwt.sign(payload, secret, { noTimestamp: true, expiresIn: "1h" })` | **Not flagged**       | **Not flagged**         |

When **`noTimestamp: true`** is set without expiry, **both JWT-05 and JWT-06** fire on the same call — JWT-05 for missing expiry generally, JWT-06 for the explicit noTimestamp misconfiguration.

## False positives and limits

| Scenario                                                            | Behavior                                                                    |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `jwt.sign(payload, secret, { noTimestamp: true, expiresIn: "1h" })` | **Not flagged** — compensating expiry present                               |
| `jwt.sign({ exp: 9999999999 }, secret, { noTimestamp: true })`      | **Not flagged** — numeric exp in payload                                    |
| `jwt.sign(payload, secret, { noTimestamp: false })`                 | **Not flagged** — noTimestamp not true                                      |
| `jwt.sign(payload, secret)` (no options)                            | **Not flagged** by JWT-06 — covered by **[CS-JWT-05](./CS-JWT-05.md)** only |
| `noTimestamp` from runtime variable without literal initializer     | **Not flagged in v1** — dynamic options not resolved                        |
| `jose`, `passport-jwt` sign helpers                                 | **Not covered** — only `jsonwebtoken`                                       |

## Fix

Either remove **`noTimestamp: true`**, or pair it with **`expiresIn`** or a payload **`exp`** claim:

```typescript
jwt.sign(payload, secret, { noTimestamp: true, expiresIn: "1h" });
```

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-JWT-06
return jwt.sign(payload, secret, { noTimestamp: true });
```

Suppress **CS-JWT-05** separately if both findings appear on the same line. See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **`jsonwebtoken`** only — sign call detection via **`jsonwebtoken-bindings`** and **`jwt-sign-options`**.

## Limitations

See [False positives and limits](#false-positives-and-limits). Dynamic options from config, cross-file constants, or non-literal expressions are not resolved in v1.3.

## Source

[`packages/ciphersins/src/rules/cs-jwt-06.ts`](https://github.com/01laky/CipherSins/blob/main/packages/ciphersins/src/rules/cs-jwt-06.ts)

## References

- [jsonwebtoken README](https://github.com/auth0/node-jsonwebtoken)
- Related: [CS-JWT-05](./CS-JWT-05.md) — JWT sign without expiry
