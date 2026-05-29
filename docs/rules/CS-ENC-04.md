# CS-ENC-04 — ECB mode cipher

| Field        | Value      |
| ------------ | ---------- |
| **ID**       | CS-ENC-04  |
| **Severity** | high       |
| **Category** | Encryption |

## Why it matters

**ECB (Electronic Codebook) mode** encrypts identical plaintext blocks to identical ciphertext blocks, leaking structure in the data. Even strong ciphers like AES are unsafe in ECB for most use cases. Prefer **GCM**, **CBC with random IV**, or other modes with proper IV/nonce handling.

**CS-ENC-03** flags **weak ciphers** (DES, RC4, Blowfish, CAST). This rule flags **ECB mode** on any tracked cipher algorithm literal ending in `-ecb`.

## Bad example

```typescript
import { createCipheriv } from "crypto";

export function encrypt(data: Buffer, key: Buffer, iv: Buffer) {
	return createCipheriv("aes-128-ecb", key, iv);
}
```

```typescript
import { createDecipheriv } from "crypto";

export function decrypt(data: Buffer, key: Buffer) {
	return createDecipheriv("aes-256-ecb", key, Buffer.alloc(0));
}
```

## Good example

```typescript
import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer, key: Buffer) {
	const iv = randomBytes(16);
	return createCipheriv("aes-256-cbc", key, iv);
}
```

```typescript
import { createCipheriv, randomBytes } from "crypto";

export function encrypt(data: Buffer, key: Buffer) {
	const iv = randomBytes(12);
	return createCipheriv("aes-256-gcm", key, iv);
}
```

## What CipherSins checks

- **Tracked cipher calls:** `createCipheriv` and `createDecipheriv` from Node **`crypto`** / **`node:crypto`** (import-aware bindings via **`crypto-cipher-bindings`**).
- **ECB algorithm literal (arg 1):** string literal matching `*-ecb` (case-insensitive), e.g. `aes-128-ecb`, `aes-256-ecb`.
- **Literal algorithm only:** non-literal algorithm expressions are not evaluated in v1.3.
- **Same-file scope only (v1).**

## Relationship to CS-ENC-01 and CS-ENC-03

| Call site                                                         | CS-ENC-01 (hardcoded key/IV)  | CS-ENC-03 (weak cipher) | CS-ENC-04 (ECB mode) |
| ----------------------------------------------------------------- | ----------------------------- | ----------------------- | -------------------- |
| `createCipheriv("aes-128-ecb", key, iv)`                          | **Not flagged** (runtime key) | **Not flagged**         | **Flagged**          |
| `createCipheriv("aes-128-ecb", "hardcoded-key", Buffer.alloc(0))` | **Flagged**                   | **Not flagged**         | **Flagged**          |
| `createCipheriv("des-cbc", key, iv)`                              | **Not flagged** (runtime key) | **Flagged**             | **Not flagged**      |
| `createCipheriv("aes-256-gcm", key, randomBytes(12))`             | **Not flagged**               | **Not flagged**         | **Not flagged**      |

**ENC-01 + ENC-04 overlap:** ECB with a hardcoded key triggers **both** rules. **ENC-03 + ENC-04:** a hypothetical `des-ecb` literal would trigger both ENC-03 (weak cipher) and ENC-04 (ECB).

## False positives and limits

| Scenario                                 | Behavior                                                               |
| ---------------------------------------- | ---------------------------------------------------------------------- |
| `createCipheriv("aes-256-gcm", key, iv)` | **Not flagged** — not ECB                                              |
| `createCipheriv("aes-128-ecb", key, iv)` | **Flagged** — ECB mode                                                 |
| `createCipheriv(algorithmVar, key, iv)`  | **Not flagged in v1** — non-literal algorithm                          |
| `createCipher("aes-256-ecb", password)`  | **Not flagged** by ENC-04 — covered by **[CS-DEC-01](./CS-DEC-01.md)** |
| Hardcoded key on ECB cipher              | **Also flagged** by **[CS-ENC-01](./CS-ENC-01.md)**                    |
| ECB cipher in `*.test.ts` / `*.spec.ts`  | **Excluded by default scan globs**, not rule logic                     |

## Fix

Switch to **AES-GCM** or **AES-CBC with a random IV per message**. Never use ECB for structured or repeated data.

## Suppressing

```typescript
// ciphersins-ignore-next-line CS-ENC-04
return createCipheriv("aes-128-ecb", key, iv);
```

See [cli.md](../cli.md#inline-suppressions).

## Library scope

- **Node `crypto` / `node:crypto`:** `createCipheriv`, `createDecipheriv` with import-aware bindings via **`crypto-cipher-bindings`** and **`ecb-cipher-algorithms`**.

## Limitations

See [False positives and limits](#false-positives-and-limits). Algorithm names from variables, config files, or cross-file constants are not resolved in v1.3.

## Source

[`packages/ciphersins/src/rules/cs-enc-04.ts`](https://github.com/01laky/CipherSins/blob/main/packages/ciphersins/src/rules/cs-enc-04.ts)

## References

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- Related: [CS-ENC-01](./CS-ENC-01.md) — hardcoded cipher key or IV
- Related: [CS-ENC-03](./CS-ENC-03.md) — weak or deprecated cipher algorithm
