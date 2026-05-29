import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const hash01GoodDir = path.join(rootDir, "fixtures/cs-hash-01/good");
const enc01BadDir = path.join(rootDir, "fixtures/cs-enc-01/bad");
const jwt01GoodDir = path.join(rootDir, "fixtures/cs-jwt-01/good");

async function scanSource(name: string, source: string) {
	const tempDir = fs.mkdtempSync(
		path.join(os.tmpdir(), "ciphersins-v13-edge-"),
	);
	const file = path.join(tempDir, name);
	fs.writeFileSync(file, source);
	try {
		return await scan({ paths: [file], cwd: tempDir });
	} finally {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

function filterByRule(findings: { ruleId: string }[], ruleId: string) {
	return findings.filter((f) => f.ruleId === ruleId);
}

describe("CS-v1.3 edge cases — HASH-04/05", () => {
	it("CS-V13-EDGE-01 scryptSync low cost in password context flags HASH-04", async () => {
		const result = await scanSource(
			"scrypt-low.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function hashPassword(password: string, salt: Buffer) {",
				"  return scryptSync(password, salt, 64, { cost: 8192 });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(1);
	});

	it("CS-V13-EDGE-02 scryptSync default no options stays clean for HASH-04", async () => {
		const result = await scanSource(
			"scrypt-default.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function hashPassword(password: string, salt: Buffer) {",
				"  return scryptSync(password, salt, 64);",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(0);
	});

	it("CS-V13-EDGE-03 argon2 timeCost 2 flags HASH-05", async () => {
		const result = await scanSource(
			"argon2-low.ts",
			[
				'import argon2 from "argon2";',
				"export async function hashPassword(password: string) {",
				"  return argon2.hash(password, { timeCost: 2, memoryCost: 65536 });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(1);
	});

	it("CS-V13-EDGE-04 argon2 timeCost 3 at boundary stays clean for HASH-05", async () => {
		const result = await scanSource(
			"argon2-boundary.ts",
			[
				'import argon2 from "argon2";',
				"export async function hashPassword(password: string) {",
				"  return argon2.hash(password, { timeCost: 3, memoryCost: 65536 });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(0);
	});

	it("CS-V13-EDGE-05 @node-rs/argon2 low timeCost flags HASH-05", async () => {
		const result = await scanSource(
			"node-rs-argon2.ts",
			[
				'import { hash } from "@node-rs/argon2";',
				"export async function hashPassword(password: string) {",
				"  return hash(password, { timeCost: 2 });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(1);
	});

	it("CS-V13-EDGE-06 scrypt low blockSize flags HASH-04", async () => {
		const result = await scanSource(
			"scrypt-blocksize.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function hashPassword(password: string, salt: Buffer) {",
				"  return scryptSync(password, salt, 64, { cost: 16384, blockSize: 4 });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(1);
	});
});

describe("CS-v1.3 edge cases — ENC-03/04", () => {
	it("CS-V13-EDGE-07 des-cbc createCipheriv flags ENC-03", async () => {
		const result = await scanSource(
			"des-cbc.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(data: Buffer, key: Buffer, iv: Buffer) {",
				'  return createCipheriv("des-cbc", key, iv);',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-03")).toHaveLength(1);
	});

	it("CS-V13-EDGE-08 aes-128-ecb flags ENC-04", async () => {
		const result = await scanSource(
			"ecb.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(data: Buffer, key: Buffer, iv: Buffer) {",
				'  return createCipheriv("aes-128-ecb", key, iv);',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-04")).toHaveLength(1);
	});

	it("CS-V13-EDGE-09 AES-256-ECB uppercase flags ENC-04", async () => {
		const result = await scanSource(
			"ecb-upper.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(key: Buffer) {",
				'  return createCipheriv("AES-256-ECB", key, Buffer.alloc(0));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-04")).toHaveLength(1);
	});

	it("CS-V13-EDGE-10 ECB plus hardcoded key flags ENC-01 and ENC-04", async () => {
		const result = await scanSource(
			"ecb-hardcoded.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc() {",
				'  return createCipheriv("aes-128-ecb", "hardcoded-key-16b", Buffer.alloc(0));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-04")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-V13-EDGE-11 chacha20-poly1305 stays clean for ENC-03", async () => {
		const result = await scanSource(
			"chacha.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(data: Buffer, key: Buffer) {",
				'  return createCipheriv("chacha20-poly1305", key, randomBytes(12));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-03")).toHaveLength(0);
	});
});

describe("CS-v1.3 edge cases — JWT-05/06", () => {
	it("CS-V13-EDGE-12 jwt.sign without expiry flags JWT-05", async () => {
		const result = await scanSource(
			"sign-no-exp.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function issue(payload: object, secret: string) {",
				"  return jwt.sign(payload, secret);",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
	});

	it("CS-V13-EDGE-13 jwt.sign with expiresIn stays clean for JWT-05", async () => {
		const result = await scanSource(
			"sign-expires.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function issue(payload: object, secret: string) {",
				"  return jwt.sign(payload, secret, { expiresIn: '1h' });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(0);
	});

	it("CS-V13-EDGE-14 noTimestamp without expiry flags JWT-05 and JWT-06", async () => {
		const result = await scanSource(
			"no-timestamp.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function issue(payload: object, secret: string) {",
				"  return jwt.sign(payload, secret, { noTimestamp: true });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-06")).toHaveLength(1);
	});

	it("CS-V13-EDGE-15 noTimestamp with expiresIn stays clean for JWT-06", async () => {
		const result = await scanSource(
			"no-ts-expires.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function issue(payload: object, secret: string) {",
				"  return jwt.sign(payload, secret, { noTimestamp: true, expiresIn: '1h' });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-JWT-06")).toHaveLength(0);
	});

	it("CS-V13-EDGE-16 sign algorithm none plus no expiry flags JWT-03 and JWT-05", async () => {
		const result = await scanSource(
			"sign-none.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function issue(payload: object, secret: string) {",
				"  return jwt.sign(payload, secret, { algorithm: 'none' });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
	});
});

describe("CS-v1.3 edge cases — RNG-02", () => {
	it("CS-V13-EDGE-17 randomBytes(15) in auth context flags RNG-02", async () => {
		const result = await scanSource(
			"rb-15.ts",
			[
				'import { randomBytes } from "crypto";',
				"export function generateSessionToken() {",
				"  return randomBytes(15).toString('hex');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(1);
	});

	it("CS-V13-EDGE-18 randomBytes(16) in auth context stays clean for RNG-02", async () => {
		const result = await scanSource(
			"rb-16.ts",
			[
				'import { randomBytes } from "crypto";',
				"export function generateSessionToken() {",
				"  return randomBytes(16).toString('hex');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(0);
	});

	it("CS-V13-EDGE-19 crypto.randomBytes member short length flags RNG-02", async () => {
		const result = await scanSource(
			"member-rb.ts",
			[
				'import crypto from "crypto";',
				"export function generateApiToken() {",
				"  return crypto.randomBytes(4).toString('hex');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(1);
	});

	it("CS-V13-EDGE-20 Math.random and randomBytes(4) in auth fn flags RNG-01 and RNG-02", async () => {
		const result = await scanSource(
			"dual-rng.ts",
			[
				'import { randomBytes } from "crypto";',
				"export function generateAuthToken() {",
				"  const a = Math.random();",
				"  const b = randomBytes(4);",
				"  return `${a}-${b.toString('hex')}`;",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-RNG-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(1);
	});
});

describe("CS-v1.3 edge cases — ENC-01 enhancement", () => {
	it("CS-V13-EDGE-21 let-bound key with random IV flags ENC-01", async () => {
		const result = await scanSource(
			"let-key.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(data: Buffer) {",
				"  let key = 'hardcoded-key-16b';",
				"  return createCipheriv('aes-256-gcm', key, randomBytes(12));",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-V13-EDGE-22 gcm-hardcoded-key-with-options fixture flags ENC-01", async () => {
		const file = path.join(enc01BadDir, "gcm-hardcoded-key-with-options.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});
});

describe("CS-v1.3 edge cases — JWT-01 enhancement", () => {
	it("CS-V13-EDGE-23 decode-with-reexport-verify good fixture stays clean for JWT-01", async () => {
		const file = path.join(jwt01GoodDir, "decode-with-reexport-verify.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-01")).toHaveLength(0);
	});

	it("CS-V13-EDGE-24 same-file export verify from jsonwebtoken suppresses decode finding", async () => {
		const result = await scanSource(
			"reexport-verify.ts",
			[
				'import jwt from "jsonwebtoken";',
				'export { verify } from "jsonwebtoken";',
				"export function read(token: string) { return jwt.decode(token); }",
				"export function validate(token: string) {",
				"  return verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-JWT-01")).toHaveLength(0);
	});
});

describe("CS-v1.3 edge cases — cross-rule", () => {
	it("CS-V13-EDGE-25 scrypt-password.ts in hash-01 good yields zero HASH-04", async () => {
		const file = path.join(hash01GoodDir, "scrypt-password.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(0);
	});

	it("CS-V13-EDGE-26 pbkdf2 md5 low iterations flags HASH-01 and HASH-03 not HASH-04", async () => {
		const result = await scanSource(
			"pbkdf2-md5.ts",
			[
				'import { pbkdf2Sync } from "crypto";',
				"export function hashPassword(password: string, salt: string) {",
				"  return pbkdf2Sync(password, salt, 1000, 32, 'md5');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-HASH-03")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(0);
	});

	it("CS-V13-EDGE-27 des plus hardcoded key flags ENC-01 and ENC-03", async () => {
		const result = await scanSource(
			"des-hardcoded.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc() {",
				'  return createCipheriv("des-cbc", "hardcoded-key-16b", Buffer.alloc(8));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-03")).toHaveLength(1);
	});

	it("CS-V13-EDGE-28 argon2 low timeCost outside password context stays clean", async () => {
		const result = await scanSource(
			"argon2-api-key.ts",
			[
				'import argon2 from "argon2";',
				"export async function deriveApiKey(apiKey: string) {",
				"  return argon2.hash(apiKey, { timeCost: 2 });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(0);
	});

	it("CS-V13-EDGE-29 scrypt async 5-arg low cost flags HASH-04", async () => {
		const result = await scanSource(
			"scrypt-async.ts",
			[
				'import { scrypt } from "crypto";',
				"export function hashPassword(password: string, salt: Buffer, cb: (err: Error | null, key: Buffer) => void) {",
				"  scrypt(password, salt, 64, { cost: 4096 }, cb);",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(1);
	});

	it("CS-V13-EDGE-30 jwt sign exp claim in payload stays clean for JWT-05", async () => {
		const result = await scanSource(
			"sign-exp-claim.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function issue(secret: string) {",
				"  return jwt.sign({ sub: 'u', exp: 9999999999 }, secret);",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(0);
	});

	it("CS-V13-EDGE-31 randomBytes short outside auth stays clean for RNG-02", async () => {
		const result = await scanSource(
			"color.ts",
			[
				'import { randomBytes } from "crypto";',
				"export function generateColor() {",
				"  return randomBytes(3).toString('hex');",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(0);
	});

	it("CS-V13-EDGE-32 createDecipheriv weak algorithm flags ENC-03", async () => {
		const result = await scanSource(
			"decipheriv-des.ts",
			[
				'import { createDecipheriv } from "crypto";',
				"export function dec(data: Buffer, key: Buffer, iv: Buffer) {",
				'  return createDecipheriv("rc4", key, iv);',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-03")).toHaveLength(1);
	});

	it("CS-V13-EDGE-33 nineteen rules active on secure snippet yields zero findings", async () => {
		const result = await scanSource(
			"secure.ts",
			[
				'import { createCipheriv, randomBytes, scryptSync } from "crypto";',
				"export function encrypt(data: Buffer, key: Buffer) {",
				"  return createCipheriv('aes-256-gcm', key, randomBytes(12));",
				"}",
				"export function hashPassword(password: string, salt: Buffer) {",
				"  return scryptSync(password, salt, 64, { cost: 16384 });",
				"}",
				"export function generateToken() {",
				"  return randomBytes(32).toString('hex');",
				"}",
			].join("\n"),
		);

		expect(result.findings).toEqual([]);
	});

	it("CS-V13-EDGE-34 scrypt low parallelization flags HASH-04", async () => {
		const result = await scanSource(
			"scrypt-parallel.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function hashPassword(password: string, salt: Buffer) {",
				"  return scryptSync(password, salt, 64, { cost: 16384, parallelization: 0 });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(1);
	});

	it("CS-V13-EDGE-35 argon2 low memoryCost flags HASH-05", async () => {
		const result = await scanSource(
			"argon2-mem.ts",
			[
				'import argon2 from "argon2";',
				"export async function hashPassword(password: string) {",
				"  return argon2.hash(password, { timeCost: 3, memoryCost: 32768 });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(1);
	});
});
