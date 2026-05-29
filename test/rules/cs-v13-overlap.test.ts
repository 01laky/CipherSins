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
const enc03BadDir = path.join(rootDir, "fixtures/cs-enc-03/bad");
const jwt05BadDir = path.join(rootDir, "fixtures/cs-jwt-05/bad");
const jwt06BadDir = path.join(rootDir, "fixtures/cs-jwt-06/bad");
const hash05BadDir = path.join(rootDir, "fixtures/cs-hash-05/bad");

async function scanSource(name: string, source: string) {
	const tempDir = fs.mkdtempSync(
		path.join(os.tmpdir(), "ciphersins-v13-overlap-"),
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

describe("CS-v1.3 overlap matrix", () => {
	it("CS-HASH-04-INT-02 scrypt-password.ts in hash-01 good yields zero HASH-04", async () => {
		const file = path.join(hash01GoodDir, "scrypt-password.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(0);
	});

	it("CS-HASH-05-INT-01 argon2-low-timecost.ts yields one HASH-05", async () => {
		const file = path.join(hash05BadDir, "argon2-low-timecost.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(1);
	});

	it("CS-ENC-03-INT-01 des-hardcoded-key.ts yields ENC-01 and ENC-03", async () => {
		const file = path.join(enc03BadDir, "des-hardcoded-key.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-03")).toHaveLength(1);
	});

	it("CS-ENC-04-INT-01 aes-128-ecb plus hardcoded key yields ENC-01 and ENC-04", async () => {
		const result = await scanSource(
			"ecb-hardcoded.ts",
			[
				'import { createCipheriv } from "crypto";',
				"export function enc() {",
				'  return createCipheriv("aes-128-ecb", "hardcoded-key-16b", Buffer.alloc(0));',
				"}",
			].join("\n"),
		);

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-04")).toHaveLength(1);
	});

	it("CS-JWT-05-INT-01 sign-none-and-no-expiry.ts yields JWT-03 and JWT-05", async () => {
		const file = path.join(jwt05BadDir, "sign-none-and-no-expiry.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
	});

	it("CS-JWT-06-INT-01 sign-no-timestamp-no-expiry.ts yields JWT-05 and JWT-06", async () => {
		const file = path.join(jwt06BadDir, "sign-no-timestamp-no-expiry.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-06")).toHaveLength(1);
	});

	it("CS-RNG-INT-01 Math.random plus randomBytes(4) in auth fn yields RNG-01 and RNG-02", async () => {
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

	it("CS-ENC-01-ENH-INT-01 gcm-hardcoded-key-with-options.ts yields one ENC-01", async () => {
		const file = path.join(enc01BadDir, "gcm-hardcoded-key-with-options.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});
});
