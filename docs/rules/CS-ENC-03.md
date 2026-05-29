# CS-ENC-03 — Weak or deprecated cipher algorithm

| Field        | Value      |
| ------------ | ---------- |
| **ID**       | CS-ENC-03  |
| **Severity** | high       |
| **Category** | Encryption |

## Why it matters

Legacy ciphers such as **DES**, **RC4**, **Blowfish (`bf`)**, and **CAST** have known weaknesses or are deprecated. Modern applications should use **AES-GCM**, **ChaCha20-Poly1305**, or other AEAD ciphers with proper key and IV management.

**CS-ENC-01** flags **hardcoded keys/IVs** regardless of algorithm. This rule flags **weak algorithm choice** on tracked `createCipheriv` / `createDecipheriv` calls.

## Bad example

```typescript
import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer, key: Buffer) {
	return createCipheriv("des-cbc", key, randomBytes(8));
}
```

```typescript
import { createDecipheriv } from "crypto";

export function decrypt(data: Buffer, key: Buffer, iv: Buffer) {
	return createDecipheriv("rc4", key, iv);
}
```

## Good example

```typescript
import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer, key: Buffer) {
	const iv = randomBytes(12);
	return createCipheriv("aes-256-gcm", key, iv);
}
```

```typescript
import { createCipheriv } from "crypto";

export function encrypt(data: Buffer, key: Buffer, iv: Buffer) {
	return createCipheriv("chacha20-poly1305", key, iv);
}
```

## What CipherSins checks

- **Tracked cipher calls:** `createCipheriv` and `createDecipheriv` from Node **`crypto`** / **`node:crypto`** (import-aware bindings via **`crypto-cipher-bindings`**).
- **Weak algorithm literal (arg 1):** string literal matching **DES** (`des`, `des-cbc`, …), **RC4** (`rc4`, `rc4-*`), **RC2** (`rc2`, `rc2-*`), **Blowfish** (`bf`, `bf-*`), or **CAST** (`cast`, `cast5`, `cast-*`, …).
- **Literal algorithm only:** non-literal algorithm expressions are not evaluated in v1.3.
- **Same-file scope only (v1).**

## Relationship to CS-ENC-01 and CS-DEC-01

| Call site                                             | CS-ENC-01 (hardcoded key/IV)  | CS-ENC-03 (weak algorithm) | CS-DEC-01 (deprecated API) |
| ----------------------------------------------------- | ----------------------------- | -------------------------- | -------------------------- |
| `createCipheriv("des-cbc", "hardcoded-key", iv)`      | **Flagged**                   | **Flagged**                | **Not flagged**            |
| `createCipheriv("aes-256-gcm", key, randomBytes(12))` | **Not flagged** (runtime key) | **Not flagged**            | **Not flagged**            |
| `createCipher("aes-256-cbc", password)`               | **Not flagged**               | **Not flagged**            | **Flagged**                |
| `createDecipheriv("bf-cbc", key, iv)`                 | **Not flagged** (runtime key) | **Flagged**                | **Not flagged**            |

**CS-DEC-01 boundary:** deprecated **`createCipher` / `createDecipher`** (EVP_BytesToKey) are covered by **[CS-DEC-01](./CS-DEC-01.md)**, not CS-ENC-03. ENC-03 applies only to **`createCipheriv` / `createDecipheriv`**.

**CS-ENC-01 overlap:** a weak cipher with a hardcoded key triggers **both** ENC-01 and ENC-03 — one finding per rule on the same call site.

## False positives and limits

| Scenario                                 | Behavior                                                                          |
| ---------------------------------------- | --------------------------------------------------------------------------------- |
| `createCipheriv("aes-256-gcm", key, iv)` | **Not flagged** — modern algorithm                                                |
| `createCipheriv("des-cbc", key, iv)`     | **Flagged** — weak DES family                                                     |
| `createCipheriv(algorithmVar, key, iv)`  | **Not flagged in v1** — non-literal algorithm                                     |
| `createCipheriv("aes-128-ecb", key, iv)` | **Not flagged** by ENC-03 — covered by **[CS-ENC-04](./CS-ENC-04.md)** (ECB mode) |
| `createCipher("des-cbc", password)`      | **Not flagged** by ENC-03 — covered by **[CS-DEC-01](./CS-DEC-01.md)**            |
| Hardcoded key on weak cipher             | **Also flagged** by **[CS-ENC-01](./CS-ENC-01.md)** when key/IV is a literal      |
| Weak cipher in `*.test.ts` / `*.spec.ts` | **Excluded by default scan globs**, not rule logic                                |

## Fix

Migrate to **AES-GCM**, **ChaCha20-Poly1305**, or another modern AEAD cipher. Load keys from a secrets manager or environment; generate IVs with `crypto.randomBytes()`.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-ENC-03
return createCipheriv("des-cbc", key, iv);
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **Node `crypto` / `node:crypto`:** `createCipheriv`, `createDecipheriv` with import-aware bindings via **`crypto-cipher-bindings`** and **`weak-cipher-algorithms`**.

## Limitations

See [False positives and limits](#false-positives-and-limits). Algorithm names from variables, config files, or cross-file constants are not resolved in v1.3. Third-party cipher wrappers are not tracked.

## Source

[`packages/ciphersins/src/rules/cs-enc-03.ts`](https://github.com/01laky/CipherSins/blob/main/packages/ciphersins/src/rules/cs-enc-03.ts)

## References

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- Related: [CS-ENC-01](./CS-ENC-01.md) — hardcoded cipher key or IV
- Related: [CS-ENC-04](./CS-ENC-04.md) — ECB mode cipher
- Related: [CS-DEC-01](./CS-DEC-01.md) — deprecated `createCipher` / `createDecipher`
