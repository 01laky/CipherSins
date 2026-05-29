import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const jwt01BadDir = path.join(rootDir, "fixtures/cs-jwt-01/bad");

async function scanSource(name: string, source: string) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ciphersins-v13-ext-"));
	const file = path.join(tempDir, name);
	fs.writeFileSync(file, source);
	try {
		return await scan({ paths: [file], cwd: tempDir });
	} finally {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

function byRule(findings: { ruleId: string }[], ruleId: string) {
	return findings.filter((f) => f.ruleId === ruleId);
}

function countRule(findings: { ruleId: string }[], ruleId: string) {
	return byRule(findings, ruleId).length;
}

describe("CS-V13-EXT HASH-04 scrypt boundaries and bindings", () => {
	it("CS-V13-EXT-01 scrypt cost 16383 flags HASH-04", async () => {
		const r = await scanSource(
			"cost-16383.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function hashPassword(p: string, s: Buffer) {",
				"  return scryptSync(p, s, 64, { cost: 16383 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(1);
	});

	it("CS-V13-EXT-02 scrypt cost 16384 at boundary stays clean for HASH-04", async () => {
		const r = await scanSource(
			"cost-16384.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function hashPassword(p: string, s: Buffer) {",
				"  return scryptSync(p, s, 64, { cost: 16384, blockSize: 8 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(0);
	});

	it("CS-V13-EXT-03 scrypt blockSize 7 flags HASH-04", async () => {
		const r = await scanSource(
			"block-7.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function hashPassword(p: string, s: Buffer) {",
				"  return scryptSync(p, s, 64, { cost: 16384, blockSize: 7 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(1);
	});

	it("CS-V13-EXT-04 scrypt blockSize 8 at boundary stays clean when cost ok", async () => {
		const r = await scanSource(
			"block-8.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function hashPassword(p: string, s: Buffer) {",
				"  return scryptSync(p, s, 64, { cost: 16384, blockSize: 8 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(0);
	});

	it("CS-V13-EXT-05 scrypt parallelization 1 at boundary stays clean", async () => {
		const r = await scanSource(
			"parallel-1.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function hashPassword(p: string, s: Buffer) {",
				"  return scryptSync(p, s, 64, { cost: 16384, blockSize: 8, parallelization: 1 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(0);
	});

	it("CS-V13-EXT-06 scrypt async 4-arg callback-only stays clean", async () => {
		const r = await scanSource(
			"async-cb-only.ts",
			[
				'import { scrypt } from "crypto";',
				"export function hashPassword(p: string, s: Buffer, cb: (e: Error | null, k: Buffer) => void) {",
				"  scrypt(p, s, 64, cb);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(0);
	});

	it("CS-V13-EXT-07 node:crypto scryptSync low cost flags HASH-04", async () => {
		const r = await scanSource(
			"node-scrypt.ts",
			[
				'import { scryptSync } from "node:crypto";',
				"export function hashPassword(p: string, s: Buffer) {",
				"  return scryptSync(p, s, 64, { cost: 1024 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(1);
	});

	it("CS-V13-EXT-08 crypto.scryptSync member low cost flags HASH-04", async () => {
		const r = await scanSource(
			"member-scrypt.ts",
			[
				'import crypto from "crypto";',
				"export function hashPassword(p: string, s: Buffer) {",
				"  return crypto.scryptSync(p, s, 64, { cost: 4096 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(1);
	});

	it("CS-V13-EXT-09 require scryptSync low cost flags HASH-04", async () => {
		const r = await scanSource(
			"require-scrypt.js",
			[
				'const crypto = require("crypto");',
				"function hashPassword(p, s) {",
				"  return crypto.scryptSync(p, s, 64, { cost: 2048 });",
				"}",
				"module.exports = { hashPassword };",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(1);
	});

	it("CS-V13-EXT-10 scrypt config.property access stays clean for HASH-04", async () => {
		const r = await scanSource(
			"config-scrypt.ts",
			[
				'import { scryptSync } from "crypto";',
				"const config = { cost: 512 };",
				"export function hashPassword(p: string, s: Buffer) {",
				"  return scryptSync(p, s, 64, { cost: config.cost });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(0);
	});

	it("CS-V13-EXT-11 scrypt shorthand cost variable flags HASH-04", async () => {
		const r = await scanSource(
			"shorthand-cost.ts",
			[
				'import { scryptSync } from "crypto";',
				"const cost = 4096;",
				"export function hashPassword(p: string, s: Buffer) {",
				"  return scryptSync(p, s, 64, { cost, blockSize: 8 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(1);
	});

	it("CS-V13-EXT-12 scrypt low cost in derivePassword naming flags HASH-04", async () => {
		const r = await scanSource(
			"derive-password.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function derivePassword(password: string, salt: Buffer) {",
				"  return scryptSync(password, salt, 32, { cost: 8192 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(1);
	});

	it("CS-V13-EXT-13 scrypt low cost without password context stays clean", async () => {
		const r = await scanSource(
			"api-key-scrypt.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function deriveApiKey(apiKey: string, salt: Buffer) {",
				"  return scryptSync(apiKey, salt, 32, { cost: 1024 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(0);
	});

	it("CS-V13-EXT-14 scryptSync with only blockSize low flags HASH-04", async () => {
		const r = await scanSource(
			"only-blocksize.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function hashPassword(p: string, s: Buffer) {",
				"  return scryptSync(p, s, 64, { blockSize: 4 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(1);
	});

	it("CS-V13-EXT-15 scryptSync with only parallelization low flags HASH-04", async () => {
		const r = await scanSource(
			"only-parallel.ts",
			[
				'import { scryptSync } from "crypto";',
				"export function hashPassword(p: string, s: Buffer) {",
				"  return scryptSync(p, s, 64, { parallelization: 0 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(1);
	});
});

describe("CS-V13-EXT HASH-05 argon2 boundaries and bindings", () => {
	it("CS-V13-EXT-16 argon2 memoryCost 65535 flags HASH-05", async () => {
		const r = await scanSource(
			"mem-65535.ts",
			[
				'import argon2 from "argon2";',
				"export async function hashPassword(p: string) {",
				"  return argon2.hash(p, { timeCost: 3, memoryCost: 65535 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-05")).toBe(1);
	});

	it("CS-V13-EXT-17 argon2 memoryCost 65536 at boundary stays clean", async () => {
		const r = await scanSource(
			"mem-65536.ts",
			[
				'import argon2 from "argon2";',
				"export async function hashPassword(p: string) {",
				"  return argon2.hash(p, { timeCost: 3, memoryCost: 65536 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-05")).toBe(0);
	});

	it("CS-V13-EXT-18 argon2 timeCost 2 flags HASH-05 timeCost 3 clean", async () => {
		const low = await scanSource(
			"tc-2.ts",
			[
				'import argon2 from "argon2";',
				"export async function hashPassword(p: string) {",
				"  return argon2.hash(p, { timeCost: 2, memoryCost: 65536 });",
				"}",
			].join("\n"),
		);
		const ok = await scanSource(
			"tc-3.ts",
			[
				'import argon2 from "argon2";',
				"export async function hashPassword(p: string) {",
				"  return argon2.hash(p, { timeCost: 3, memoryCost: 65536 });",
				"}",
			].join("\n"),
		);
		expect(countRule(low.findings, "CS-HASH-05")).toBe(1);
		expect(countRule(ok.findings, "CS-HASH-05")).toBe(0);
	});

	it("CS-V13-EXT-19 argon2 hashSync low timeCost flags HASH-05", async () => {
		const r = await scanSource(
			"hash-sync.ts",
			[
				'import { hashSync } from "argon2";',
				"export function hashPassword(p: string) {",
				"  return hashSync(p, { timeCost: 1, memoryCost: 65536 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-05")).toBe(1);
	});

	it("CS-V13-EXT-20 argon2 default import member hash low flags HASH-05", async () => {
		const r = await scanSource(
			"member-hash.ts",
			[
				'import argon2 from "argon2";',
				"export async function hashPassword(p: string) {",
				"  return argon2.hash(p, { timeCost: 2 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-05")).toBe(1);
	});

	it("CS-V13-EXT-21 @node-rs/argon2 hashSync low memory flags HASH-05", async () => {
		const r = await scanSource(
			"node-rs-sync.ts",
			[
				'import { hashSync } from "@node-rs/argon2";',
				"export function hashPassword(p: string) {",
				"  return hashSync(p, { timeCost: 3, memoryCost: 8192 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-05")).toBe(1);
	});

	it("CS-V13-EXT-22 argon2 verify call does not flag HASH-05", async () => {
		const r = await scanSource(
			"verify-only.ts",
			[
				'import argon2 from "argon2";',
				"export async function checkPassword(hash: string, p: string) {",
				"  return argon2.verify(hash, p);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-05")).toBe(0);
	});

	it("CS-V13-EXT-23 argon2 variable options object stays clean", async () => {
		const r = await scanSource(
			"var-options.ts",
			[
				'import argon2 from "argon2";',
				"const opts = { timeCost: 1, memoryCost: 1024 };",
				"export async function hashPassword(p: string) {",
				"  return argon2.hash(p, opts);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-05")).toBe(0);
	});

	it("CS-V13-EXT-24 argon2 shorthand timeCost variable flags HASH-05", async () => {
		const r = await scanSource(
			"shorthand-tc.ts",
			[
				'import argon2 from "argon2";',
				"const timeCost = 2;",
				"export async function hashPassword(p: string) {",
				"  return argon2.hash(p, { timeCost, memoryCost: 65536 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-05")).toBe(1);
	});

	it("CS-V13-EXT-25 require argon2 low params flags HASH-05", async () => {
		const r = await scanSource(
			"require-argon2.js",
			[
				'const argon2 = require("argon2");',
				"async function hashPassword(p) {",
				"  return argon2.hash(p, { timeCost: 2, memoryCost: 65536 });",
				"}",
				"module.exports = { hashPassword };",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-05")).toBe(1);
	});

	it("CS-V13-EXT-26 argon2 both params low yields single HASH-05 finding", async () => {
		const r = await scanSource(
			"both-low.ts",
			[
				'import argon2 from "argon2";',
				"export async function hashPassword(p: string) {",
				"  return argon2.hash(p, { timeCost: 1, memoryCost: 4096 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-05")).toBe(1);
	});
});

describe("CS-V13-EXT ENC-03 weak cipher algorithms", () => {
	const weakCases: Array<[string, string]> = [
		["rc2-cbc", "rc2-cbc"],
		["rc4-upper", "RC4"],
		["bf-cbc", "bf-cbc"],
		["cast5-cbc", "cast5-cbc"],
		["des-ede3", "des-ede3-cbc"],
		["des-alone", "des"],
	];

	for (const [slug, algo] of weakCases) {
		it(`CS-V13-EXT-ENC03-${slug} createCipheriv ${algo} flags ENC-03`, async () => {
			const r = await scanSource(
				`${slug}.ts`,
				[
					'import { createCipheriv } from "crypto";',
					"export function enc(k: Buffer, iv: Buffer) {",
					`  return createCipheriv("${algo}", k, iv);`,
					"}",
				].join("\n"),
			);
			expect(countRule(r.findings, "CS-ENC-03")).toBe(1);
		});
	}

	it("CS-V13-EXT-27 createCipher des-cbc flags DEC-01 not ENC-03", async () => {
		const r = await scanSource(
			"deprecated-des.ts",
			[
				'import { createCipher } from "crypto";',
				"export function enc(p: string) {",
				'  return createCipher("des-cbc", p);',
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-DEC-01")).toBe(1);
		expect(countRule(r.findings, "CS-ENC-03")).toBe(0);
	});

	it("CS-V13-EXT-28 variable cipher algorithm stays clean for ENC-03", async () => {
		const r = await scanSource(
			"var-algo.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(k: Buffer, algo: string) {",
				"  return createCipheriv(algo, k, randomBytes(16));",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-03")).toBe(0);
	});

	it("CS-V13-EXT-29 node:crypto weak cipher flags ENC-03", async () => {
		const r = await scanSource(
			"node-weak.ts",
			[
				'import { createCipheriv } from "node:crypto";',
				"export function enc(k: Buffer, iv: Buffer) {",
				'  return createCipheriv("rc4", k, iv);',
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-03")).toBe(1);
	});

	it("CS-V13-EXT-30 createDecipheriv cast flags ENC-03", async () => {
		const r = await scanSource(
			"decipher-cast.ts",
			[
				'import { createDecipheriv } from "crypto";',
				"export function dec(d: Buffer, k: Buffer, iv: Buffer) {",
				'  return createDecipheriv("cast-cbc", k, iv);',
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-03")).toBe(1);
	});
});

describe("CS-V13-EXT ENC-04 ECB mode", () => {
	it("CS-V13-EXT-31 createDecipheriv aes-256-ecb flags ENC-04", async () => {
		const r = await scanSource(
			"decipher-ecb.ts",
			[
				'import { createDecipheriv } from "crypto";',
				"export function dec(d: Buffer, k: Buffer) {",
				'  return createDecipheriv("aes-256-ecb", k, Buffer.alloc(0));',
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-04")).toBe(1);
	});

	it("CS-V13-EXT-32 des-ecb flags ENC-04 and ENC-03", async () => {
		const r = await scanSource(
			"des-ecb.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(k: Buffer) {",
				'  return createCipheriv("des-ecb", k, Buffer.alloc(0));',
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-04")).toBe(1);
		expect(countRule(r.findings, "CS-ENC-03")).toBe(1);
	});

	it("CS-V13-EXT-33 aes-256-cbc stays clean for ENC-04", async () => {
		const r = await scanSource(
			"cbc-clean.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(k: Buffer) {",
				'  return createCipheriv("aes-256-cbc", k, randomBytes(16));',
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-04")).toBe(0);
	});

	it("CS-V13-EXT-34 require createCipheriv ecb flags ENC-04", async () => {
		const r = await scanSource(
			"require-ecb.js",
			[
				'const crypto = require("crypto");',
				"function enc(k) {",
				'  return crypto.createCipheriv("aes-128-ecb", k, Buffer.alloc(0));',
				"}",
				"module.exports = { enc };",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-04")).toBe(1);
	});

	it("CS-V13-EXT-35 ecb hardcoded key triple ENC-01 ENC-03 ENC-04", async () => {
		const r = await scanSource(
			"ecb-des-key.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc() {",
				'  return createCipheriv("des-ecb", "hardcoded-key-16b", Buffer.alloc(0));',
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-01")).toBe(1);
		expect(countRule(r.findings, "CS-ENC-03")).toBe(1);
		expect(countRule(r.findings, "CS-ENC-04")).toBe(1);
	});
});

describe("CS-V13-EXT JWT-05 and JWT-06 sign expiry", () => {
	it("CS-V13-EXT-36 sign empty options object flags JWT-05", async () => {
		const r = await scanSource(
			"empty-opts.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function issue(p: object, s: string) {",
				"  return jwt.sign(p, s, {});",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-05")).toBe(1);
	});

	it("CS-V13-EXT-37 sign expiresIn numeric literal stays clean JWT-05", async () => {
		const r = await scanSource(
			"expires-num.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function issue(p: object, s: string) {",
				"  return jwt.sign(p, s, { expiresIn: 3600 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-05")).toBe(0);
	});

	it("CS-V13-EXT-38 sign bound expiresIn const stays clean JWT-05", async () => {
		const r = await scanSource(
			"bound-expires.ts",
			[
				'import jwt from "jsonwebtoken";',
				"const expiresIn = '2h';",
				"export function issue(p: object, s: string) {",
				"  return jwt.sign(p, s, { expiresIn });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-05")).toBe(0);
	});

	it("CS-V13-EXT-39 sign bound exp claim in payload stays clean JWT-05", async () => {
		const r = await scanSource(
			"bound-exp.ts",
			[
				'import jwt from "jsonwebtoken";',
				"const exp = 9999999999;",
				"export function issue(s: string) {",
				"  return jwt.sign({ sub: 'u', exp }, s);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-05")).toBe(0);
	});

	it("CS-V13-EXT-40 sign nbf only still flags JWT-05", async () => {
		const r = await scanSource(
			"nbf-only.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function issue(s: string) {",
				"  return jwt.sign({ nbf: 1 }, s);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-05")).toBe(1);
	});

	it("CS-V13-EXT-41 sign 4-arg expiresIn callback stays clean JWT-05", async () => {
		const r = await scanSource(
			"sign-cb-exp.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function issue(p: object, s: string, cb: jwt.SignCallback) {",
				"  return jwt.sign(p, s, { expiresIn: '1h' }, cb);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-05")).toBe(0);
	});

	it("CS-V13-EXT-42 named sign import alias without expiry flags JWT-05", async () => {
		const r = await scanSource(
			"sign-alias.ts",
			[
				'import { sign as jwtSign } from "jsonwebtoken";',
				"export function issue(p: object, s: string) {",
				"  return jwtSign(p, s);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-05")).toBe(1);
	});

	it("CS-V13-EXT-43 inline require sign without expiry flags JWT-05", async () => {
		const r = await scanSource(
			"inline-sign.js",
			[
				"function issue(p, s) {",
				"  return require('jsonwebtoken').sign(p, s);",
				"}",
				"module.exports = { issue };",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-05")).toBe(1);
	});

	it("CS-V13-EXT-44 noTimestamp const true bound flags JWT-05 and JWT-06", async () => {
		const r = await scanSource(
			"bound-notimestamp.ts",
			[
				'import jwt from "jsonwebtoken";',
				"const noTimestamp = true;",
				"export function issue(p: object, s: string) {",
				"  return jwt.sign(p, s, { noTimestamp });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-05")).toBe(1);
		expect(countRule(r.findings, "CS-JWT-06")).toBe(1);
	});

	it("CS-V13-EXT-45 noTimestamp with exp claim stays clean JWT-06", async () => {
		const r = await scanSource(
			"nts-exp.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function issue(s: string) {",
				"  return jwt.sign({ exp: 9999999999 }, s, { noTimestamp: true });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-06")).toBe(0);
	});

	it("CS-V13-EXT-46 sign with algorithm HS256 only still flags JWT-05", async () => {
		const r = await scanSource(
			"alg-only.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function issue(p: object, s: string) {",
				"  return jwt.sign(p, s, { algorithm: 'HS256' });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-05")).toBe(1);
	});
});

describe("CS-V13-EXT RNG-02 randomBytes length", () => {
	it("CS-V13-EXT-47 randomBytes(0) in session context flags RNG-02", async () => {
		const r = await scanSource(
			"rb-0.ts",
			[
				'import { randomBytes } from "crypto";',
				"export function generateSessionId() {",
				"  return randomBytes(0).toString('hex');",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-RNG-02")).toBe(1);
	});

	it("CS-V13-EXT-48 randomBytes(1) in otp context flags RNG-02", async () => {
		const r = await scanSource(
			"rb-1.ts",
			[
				'import { randomBytes } from "crypto";',
				"export function generateOtpToken() {",
				"  return randomBytes(1).toString('hex');",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-RNG-02")).toBe(1);
	});

	it("CS-V13-EXT-49 randomBytes variable n=14 flags RNG-02", async () => {
		const r = await scanSource(
			"rb-var-14.ts",
			[
				'import { randomBytes } from "crypto";',
				"const n = 14;",
				"export function generateAuthSecret() {",
				"  return randomBytes(n);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-RNG-02")).toBe(1);
	});

	it("CS-V13-EXT-50 node:crypto randomBytes short flags RNG-02", async () => {
		const r = await scanSource(
			"node-rb.ts",
			[
				'import { randomBytes } from "node:crypto";',
				"export function generateApiToken() {",
				"  return randomBytes(8);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-RNG-02")).toBe(1);
	});

	it("CS-V13-EXT-51 auth class method short randomBytes flags RNG-02", async () => {
		const r = await scanSource(
			"class-token.ts",
			[
				'import { randomBytes } from "crypto";',
				"export class SessionTokenService {",
				"  create() { return randomBytes(6); }",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-RNG-02")).toBe(1);
	});

	it("CS-V13-EXT-52 randomUUID in auth context stays clean RNG-02", async () => {
		const r = await scanSource(
			"uuid.ts",
			[
				'import { randomUUID } from "crypto";',
				"export function generateSessionToken() {",
				"  return randomUUID();",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-RNG-02")).toBe(0);
	});

	it("CS-V13-EXT-53 variable length randomBytes stays clean RNG-02", async () => {
		const r = await scanSource(
			"var-len.ts",
			[
				'import { randomBytes } from "crypto";',
				"export function generateSessionToken(len: number) {",
				"  return randomBytes(len);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-RNG-02")).toBe(0);
	});

	it("CS-V13-EXT-54 require randomBytes short in auth flags RNG-02", async () => {
		const r = await scanSource(
			"require-rb.js",
			[
				'const crypto = require("crypto");',
				"function generateSecretToken() {",
				"  return crypto.randomBytes(4);",
				"}",
				"module.exports = { generateSecretToken };",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-RNG-02")).toBe(1);
	});
});

describe("CS-V13-EXT ENC-01 const and let resolution", () => {
	it("CS-V13-EXT-55 const Buffer.from key flags ENC-01", async () => {
		const r = await scanSource(
			"buf-from-key.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(d: Buffer) {",
				'  const key = Buffer.from("hardcoded-key-16b");',
				"  return createCipheriv('aes-256-gcm', key, randomBytes(12));",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-01")).toBe(1);
	});

	it("CS-V13-EXT-56 const iv literal flags ENC-01", async () => {
		const r = await scanSource(
			"const-iv.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(k: Buffer) {",
				"  const iv = 'static-iv-1234567';",
				"  return createCipheriv('aes-256-cbc', k, iv);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-01")).toBe(1);
	});

	it("CS-V13-EXT-57 let key reassigned still flags ENC-01 on use", async () => {
		const r = await scanSource(
			"let-reassign.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(d: Buffer) {",
				"  let key = 'hardcoded-key-16b';",
				"  key = key;",
				"  return createCipheriv('aes-256-gcm', key, randomBytes(12));",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-01")).toBe(1);
	});

	it("CS-V13-EXT-58 module-level const key used in cipheriv flags ENC-01", async () => {
		const r = await scanSource(
			"module-key.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"const key = 'hardcoded-key-16b';",
				"export function enc(d: Buffer) {",
				"  return createCipheriv('aes-256-gcm', key, randomBytes(12));",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-01")).toBe(1);
	});

	it("CS-V13-EXT-59 identifier from env key stays clean ENC-01", async () => {
		const r = await scanSource(
			"env-key.ts",
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(d: Buffer) {",
				"  const key = process.env.CIPHER_KEY!;",
				"  return createCipheriv('aes-256-gcm', key, randomBytes(12));",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-ENC-01")).toBe(0);
	});
});

describe("CS-V13-EXT JWT-01 re-export verify enhancement", () => {
	it("CS-V13-EXT-60 decode-reexport-no-verify-call bad fixture flags JWT-01", async () => {
		const file = path.join(jwt01BadDir, "decode-reexport-no-verify-call.ts");
		const r = await scan({ paths: [file], cwd: rootDir });
		expect(countRule(r.findings, "CS-JWT-01")).toBe(1);
	});

	it("CS-V13-EXT-61 reexport verify without verify call still flags decode", async () => {
		const r = await scanSource(
			"reexport-no-call.ts",
			[
				'import jwt from "jsonwebtoken";',
				'export { verify } from "jsonwebtoken";',
				"export function read(token: string) {",
				"  return jwt.decode(token);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-01")).toBe(1);
	});

	it("CS-V13-EXT-62 import verify plus decode in same fn stays clean JWT-01", async () => {
		const r = await scanSource(
			"same-fn-verify.ts",
			[
				'import jwt, { verify } from "jsonwebtoken";',
				"export function handle(token: string, secret: string) {",
				"  const payload = jwt.decode(token);",
				"  verify(token, secret, { algorithms: ['HS256'] });",
				"  return payload;",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-01")).toBe(0);
	});

	it("CS-V13-EXT-63 multiple decode with reexport and verify stays clean", async () => {
		const r = await scanSource(
			"multi-decode.ts",
			[
				'import jwt from "jsonwebtoken";',
				'export { verify } from "jsonwebtoken";',
				"export function readA(t: string) { return jwt.decode(t); }",
				"export function readB(t: string) { return jwt.decode(t); }",
				"export function validate(t: string) {",
				"  return verify(t, 's', { algorithms: ['HS256'] });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-01")).toBe(0);
	});
});

describe("CS-V13-EXT cross-rule and regression combos", () => {
	it("CS-V13-EXT-64 full insecure auth stack yields multiple rule hits", async () => {
		const r = await scanSource(
			"insecure-stack.ts",
			[
				'import jwt from "jsonwebtoken";',
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function generateSessionToken(p: object, s: string) {",
				"  const tok = jwt.sign(p, s, { algorithm: 'none' });",
				"  const sid = Math.random().toString(36);",
				"  const key = 'hardcoded-key-16b';",
				"  createCipheriv('aes-128-ecb', key, Buffer.alloc(0));",
				"  randomBytes(4);",
				"  return { tok, sid };",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-03")).toBeGreaterThanOrEqual(1);
		expect(countRule(r.findings, "CS-JWT-05")).toBeGreaterThanOrEqual(1);
		expect(countRule(r.findings, "CS-RNG-01")).toBeGreaterThanOrEqual(1);
		expect(countRule(r.findings, "CS-RNG-02")).toBeGreaterThanOrEqual(1);
		expect(countRule(r.findings, "CS-ENC-01")).toBeGreaterThanOrEqual(1);
		expect(countRule(r.findings, "CS-ENC-04")).toBeGreaterThanOrEqual(1);
	});

	it("CS-V13-EXT-65 argon2 bcrypt scrypt secure kdf snippet stays clean", async () => {
		const r = await scanSource(
			"secure-kdf.ts",
			[
				'import { scryptSync } from "crypto";',
				'import argon2 from "argon2";',
				'import bcrypt from "bcrypt";',
				"export async function hashPassword(p: string, s: Buffer) {",
				"  scryptSync(p, s, 64, { cost: 16384 });",
				"  await argon2.hash(p, { timeCost: 3, memoryCost: 65536 });",
				"  return bcrypt.hash(p, 12);",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(0);
		expect(countRule(r.findings, "CS-HASH-05")).toBe(0);
	});

	it("CS-V13-EXT-66 jwt verify-only file does not flag JWT-05 or JWT-06", async () => {
		const r = await scanSource(
			"verify-file.ts",
			[
				'import jwt from "jsonwebtoken";',
				"export function validate(t: string, s: string) {",
				"  return jwt.verify(t, s, { algorithms: ['HS256'] });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-JWT-05")).toBe(0);
		expect(countRule(r.findings, "CS-JWT-06")).toBe(0);
	});

	it("CS-V13-EXT-67 scrypt and argon2 both weak in same password fn yields 2 findings", async () => {
		const r = await scanSource(
			"dual-kdf-weak.ts",
			[
				'import { scryptSync } from "crypto";',
				'import argon2 from "argon2";',
				"export async function hashPassword(p: string, s: Buffer) {",
				"  scryptSync(p, s, 64, { cost: 1024 });",
				"  return argon2.hash(p, { timeCost: 1 });",
				"}",
			].join("\n"),
		);
		expect(countRule(r.findings, "CS-HASH-04")).toBe(1);
		expect(countRule(r.findings, "CS-HASH-05")).toBe(1);
	});

	it("CS-V13-EXT-68 nineteen rules secure jwt sign encrypt token snippet clean", async () => {
		const r = await scanSource(
			"full-secure.ts",
			[
				'import jwt from "jsonwebtoken";',
				'import { createCipheriv, randomBytes, scryptSync } from "crypto";',
				"export function issue(p: object, s: string) {",
				"  return jwt.sign(p, s, { expiresIn: '1h', algorithm: 'HS256' });",
				"}",
				"export function encrypt(d: Buffer, k: Buffer) {",
				"  return createCipheriv('aes-256-gcm', k, randomBytes(12));",
				"}",
				"export function hashPassword(p: string, s: Buffer) {",
				"  return scryptSync(p, s, 64, { cost: 16384 });",
				"}",
				"export function token() { return randomBytes(32).toString('hex'); }",
			].join("\n"),
		);
		expect(r.findings).toEqual([]);
	});
});
