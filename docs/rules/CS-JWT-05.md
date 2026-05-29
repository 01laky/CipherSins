# CS-JWT-05 — JWT sign without expiry

| Field        | Value     |
| ------------ | --------- |
| **ID**       | CS-JWT-05 |
| **Severity** | medium    |
| **Category** | JWT       |

## Why it matters

JWTs without an expiration (`exp` claim or `expiresIn` sign option) remain valid indefinitely if the signing secret is not rotated. Stolen tokens can be replayed forever. Always set a bounded lifetime on issued tokens.

**CS-JWT-04** flags **`ignoreExpiration: true`** on verify — disabling expiry checks at validation time. **CS-JWT-05** flags **missing expiry at sign time** when the token is created.

## Bad example

```typescript
import jwt from "jsonwebtoken";

export function issueToken(payload: object, secret: string) {
	return jwt.sign(payload, secret);
}
```

```typescript
import jwt from "jsonwebtoken";

export function issueToken(payload: object, secret: string) {
	return jwt.sign(payload, secret, {});
}
```

## Good example

```typescript
import jwt from "jsonwebtoken";

export function issueToken(payload: object, secret: string) {
	return jwt.sign(payload, secret, { expiresIn: "1h" });
}
```

```typescript
import jwt from "jsonwebtoken";

export function issueToken(payload: object, secret: string) {
	return jwt.sign(
		{ ...payload, exp: Math.floor(Date.now() / 1000) + 3600 },
		secret,
	);
}
```

## What CipherSins checks

- **Tracked sign calls:** `jwt.sign()` from **`jsonwebtoken`** (default/named/namespace import, CommonJS `require`, destructured require).
- **Missing expiry:** no `expiresIn` in sign options object literal **and** no numeric `exp` in the payload object literal.
- **Same-file resolution:** `expiresIn` / `exp` via identifier bound to a same-file string or numeric literal counts as present.
- **Variable-bound options:** sign options passed via same-file `const`/`let` identifier resolved to an object literal with `expiresIn`.
- **`nbf` alone does not count** — not-before without expiry is still flagged.

## Relationship to CS-JWT-03

| Sign call pattern                                                    | CS-JWT-03 (`none` algorithm) | CS-JWT-05 (no expiry) |
| -------------------------------------------------------------------- | ---------------------------- | --------------------- |
| `jwt.sign(payload, secret)`                                          | **Not flagged**              | **Flagged**           |
| `jwt.sign(payload, secret, { expiresIn: "1h" })`                     | **Not flagged**              | **Not flagged**       |
| `jwt.sign(payload, secret, { algorithm: "none" })`                   | **Flagged**                  | **Flagged**           |
| `jwt.sign(payload, secret, { algorithm: "HS256", expiresIn: "1h" })` | **Not flagged**              | **Not flagged**       |

Both rules can fire on the same **`jwt.sign()`** call when **`algorithm: 'none'`** is combined with missing expiry.

**CS-JWT-06 overlap:** `jwt.sign(..., { noTimestamp: true })` without expiry triggers **both JWT-05 and JWT-06** — see **[CS-JWT-06](./CS-JWT-06.md)**.

## False positives and limits

| Scenario                                                          | Behavior                                                          |
| ----------------------------------------------------------------- | ----------------------------------------------------------------- |
| `jwt.sign(payload, secret, { expiresIn: "1h" })`                  | **Not flagged** — explicit expiry                                 |
| `jwt.sign({ exp: 9999999999 }, secret)`                           | **Not flagged** — numeric exp in payload                          |
| `jwt.sign(payload, secret, { noTimestamp: true })`                | **Flagged** by JWT-05 **and** **[CS-JWT-06](./CS-JWT-06.md)**     |
| `jwt.sign(payload, secret, { nbf: Math.floor(Date.now()/1000) })` | **Flagged** — nbf alone is not expiry                             |
| `jwt.verify(token, secret, { algorithms: ["HS256"] })`            | **Not flagged** — verify-only; use CS-JWT-04 for ignoreExpiration |
| Expiry from runtime variable without literal initializer          | **Not flagged in v1** — cross-file / dynamic expiry not resolved  |
| `jose`, `passport-jwt` sign helpers                               | **Not covered** — only `jsonwebtoken`                             |

## Fix

Add **`expiresIn`** to sign options or a numeric **`exp`** claim in the payload:

```typescript
jwt.sign(payload, secret, { expiresIn: "1h", algorithm: "HS256" });
```

See **[CS-JWT-03](./CS-JWT-03.md)** for `none` algorithm bypass and **[CS-JWT-04](./CS-JWT-04.md)** for verify-side expiration disabling.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-JWT-05
return jwt.sign(payload, secret);
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **`jsonwebtoken`** only — sign call detection via **`jsonwebtoken-bindings`** and **`jwt-sign-options`**.

## Limitations

See [False positives and limits](#false-positives-and-limits). Dynamic expiry from config, cross-file helpers, or non-literal expressions is not resolved in v1.3.

## Source

[`packages/ciphersins/src/rules/cs-jwt-05.ts`](https://github.com/01laky/CipherSins/blob/main/packages/ciphersins/src/rules/cs-jwt-05.ts)

## References

- [jsonwebtoken README](https://github.com/auth0/node-jsonwebtoken)
- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- Related: [CS-JWT-03](./CS-JWT-03.md) — algorithm none / bypass
- Related: [CS-JWT-04](./CS-JWT-04.md) — missing exp validation on verify
- Related: [CS-JWT-06](./CS-JWT-06.md) — noTimestamp without expiry
