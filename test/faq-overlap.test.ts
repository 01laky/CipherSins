import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { scan } from "ciphersins";

async function scanSource(name: string, source: string) {
	const tempDir = fs.mkdtempSync(
		path.join(os.tmpdir(), "ciphersins-faq-overlap-"),
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

describe("CS-FAQ overlap matrix integration", () => {
	it("CS-FAQ-INT-01 pbkdf2Sync md5 low iterations triggers HASH-01 and HASH-03", async () => {
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
	});

	it("CS-FAQ-INT-02 scryptSync low cost triggers HASH-04", async () => {
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

	it("CS-FAQ-INT-03 argon2 low timeCost triggers HASH-05", async () => {
		const result = await scanSource(
			"argon2-low.ts",
			[
				'import argon2 from "argon2";',
				"export async function hashPassword(password: string) {",
				"  return argon2.hash(password, { timeCost: 2 });",
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(1);
	});

	it("CS-FAQ-INT-04 createCipheriv des-cbc with hardcoded key triggers ENC-01 and ENC-03", async () => {
		const result = await scanSource(
			"des-hardcoded.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc() {",
				'  return createCipheriv("des-cbc", "key16bytes!!!!!!", Buffer.alloc(8));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-03")).toHaveLength(1);
	});

	it("CS-FAQ-INT-05 createCipheriv aes-128-ecb triggers ENC-04", async () => {
		const result = await scanSource(
			"ecb.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(key: Buffer) {",
				'  return createCipheriv("aes-128-ecb", key, Buffer.alloc(0));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-04")).toHaveLength(1);
	});

	it("CS-FAQ-INT-06 jwt.sign without expiry triggers JWT-05", async () => {
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

	it("CS-FAQ-INT-07 jwt.sign noTimestamp without expiry triggers JWT-05 and JWT-06", async () => {
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

	it("CS-FAQ-INT-08 jwt.sign algorithm none without expiry triggers JWT-03 and JWT-05", async () => {
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

	it("CS-FAQ-INT-09 Math.random and randomBytes(4) in auth fn triggers RNG-01 and RNG-02", async () => {
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
