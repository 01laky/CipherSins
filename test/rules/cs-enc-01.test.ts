import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csEnc01Rule,
	parseSourceFile,
	scan,
} from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const enc01BadDir = path.join(rootDir, "fixtures/cs-enc-01/bad");
const enc01GoodDir = path.join(rootDir, "fixtures/cs-enc-01/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const ALL_RULE_IDS = [
	"CS-JWT-01",
	"CS-JWT-02",
	"CS-JWT-03",
	"CS-JWT-04",
	"CS-JWT-05",
	"CS-JWT-06",
	"CS-CMP-01",
	"CS-RNG-01",
	"CS-RNG-02",
	"CS-HASH-01",
	"CS-HASH-02",
	"CS-HASH-03",
	"CS-HASH-04",
	"CS-HASH-05",
	"CS-ENC-01",
	"CS-ENC-02",
	"CS-ENC-03",
	"CS-ENC-04",
	"CS-DEC-01",
];

const CS_ENC_01_MESSAGE =
	"Hardcoded key or IV passed to createCipheriv/createDecipheriv; use environment variables, a KMS, or randomBytes for IVs.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-enc-01", segment, name);
}

function filterByRule(findings: { ruleId: string }[], ruleId: string) {
	return findings.filter((f) => f.ruleId === ruleId);
}

function findingSignature(finding: {
	ruleId: string;
	file: string;
	line: number;
	column: number;
}) {
	return `${path.basename(finding.file)}:${finding.line}:${finding.column}:${finding.ruleId}`;
}

describe("CS-ENC-01 rule registry", () => {
	it("CS-ENC-01-01 registers CS-ENC-01 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-ENC-01")).toBe(true);
	});

	it("CS-ENC-01-02 csEnc01Rule metadata matches rule spec", () => {
		expect(csEnc01Rule.id).toBe("CS-ENC-01");
		expect(csEnc01Rule.title).toBe("Hardcoded cipher key or IV");
		expect(csEnc01Rule.severity).toBe("medium");
	});

	it("CS-ENC-01-03 csEnc01Rule is registered at index 14 after CS-HASH-05", () => {
		const fromRegistry = allRules.find((rule) => rule.id === "CS-ENC-01");
		expect(fromRegistry).toBeDefined();
		expect(fromRegistry).toBe(csEnc01Rule);
		expect(allRules[14]).toBe(csEnc01Rule);
		expect(allRules.map((rule) => rule.id)).toEqual(ALL_RULE_IDS);
	});
});

describe("CS-ENC-01 directory scans", () => {
	it("CS-ENC-01-04 flags bad fixtures with medium severity", async () => {
		const result = await scan({ paths: [enc01BadDir], cwd: rootDir });
		const encFindings = filterByRule(result.findings, "CS-ENC-01");

		expect(encFindings).toHaveLength(8);
		expect(result.scannedFiles).toHaveLength(8);
		expect(encFindings.every((f) => f.severity === "medium")).toBe(true);
		expect(encFindings.every((f) => f.message === CS_ENC_01_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-ENC-01-05 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [enc01GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-ENC-01 per-file bad fixtures", () => {
	it("CS-ENC-01-06 cipheriv-hardcoded-key.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "cipheriv-hardcoded-key.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-07 cipheriv-hardcoded-iv.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "cipheriv-hardcoded-iv.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-08 cipheriv-buffer-from-literal.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "cipheriv-buffer-from-literal.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-09 decipheriv-hardcoded-key.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decipheriv-hardcoded-key.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-10 namespace-crypto-cipheriv.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "namespace-crypto-cipheriv.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-11 node-crypto-hardcoded-key.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "node-crypto-hardcoded-key.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-12 require-destructured-cipheriv.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-destructured-cipheriv.js")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-13 gcm-hardcoded-key-with-options.ts flags CS-ENC-01 without CS-ENC-02 overlap", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gcm-hardcoded-key-with-options.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-02")).toHaveLength(0);
		expect(result.scannedFiles).toHaveLength(1);
	});
});

describe("CS-ENC-01 per-file good fixtures", () => {
	it("CS-ENC-01-14 cipheriv-env-key.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "cipheriv-env-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-01-15 cipheriv-param-key.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "cipheriv-param-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-01-16 cipheriv-random-iv.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "cipheriv-random-iv.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-01-17 no-cipher-calls.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "no-cipher-calls.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-01-18 no-crypto-import.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "no-crypto-import.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-01-19 node-crypto-env-key.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "node-crypto-env-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-ENC-01 finding shape", () => {
	it("CS-ENC-01-20 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "cipheriv-hardcoded-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-ENC-01\.md$/);
	});

	it("CS-ENC-01-21 finding snippet references createCipheriv or hardcoded material", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "cipheriv-hardcoded-key.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.snippet).toMatch(/createCipheriv|hardcoded/i);
	});

	it("CS-ENC-01-22 summary.medium equals CS-ENC-01 finding count for bad directory", async () => {
		const result = await scan({ paths: [enc01BadDir], cwd: rootDir });
		const encFindings = filterByRule(result.findings, "CS-ENC-01");

		expect(result.summary.medium).toBe(encFindings.length);
		expect(result.summary.medium).toBe(8);
	});
});

describe("CS-ENC-01 const key resolution enhancement", () => {
	it("CS-ENC-01-26 gcm-hardcoded-key-with-options.ts yields exactly one ENC-01 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gcm-hardcoded-key-with-options.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});

	it("CS-ENC-01-27 let-bound key with random IV flags CS-ENC-01", async () => {
		const tempDir = fs.mkdtempSync(
			path.join(os.tmpdir(), "ciphersins-enc01-let-"),
		);
		const file = path.join(tempDir, "let-key.ts");
		fs.writeFileSync(
			file,
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(data: Buffer) {",
				"  let key = 'hardcoded-key-16b';",
				"  return createCipheriv('aes-256-gcm', key, randomBytes(12));",
				"}",
			].join("\n"),
		);
		try {
			const result = await scan({ paths: [file], cwd: tempDir });
			expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("CS-ENC-01-28 const-bound iv with param key flags CS-ENC-01", async () => {
		const tempDir = fs.mkdtempSync(
			path.join(os.tmpdir(), "ciphersins-enc01-const-iv-"),
		);
		const file = path.join(tempDir, "const-iv.ts");
		fs.writeFileSync(
			file,
			[
				'import { createCipheriv } from "crypto";',
				"export function enc(data: Buffer, key: Buffer) {",
				"  const iv = 'static-iv-123456';",
				"  return createCipheriv('aes-256-cbc', key, iv);",
				"}",
			].join("\n"),
		);
		try {
			const result = await scan({ paths: [file], cwd: tempDir });
			expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("CS-ENC-01-29 const key from process.env stays clean for CS-ENC-01", async () => {
		const tempDir = fs.mkdtempSync(
			path.join(os.tmpdir(), "ciphersins-enc01-env-"),
		);
		const file = path.join(tempDir, "env-key.ts");
		fs.writeFileSync(
			file,
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(data: Buffer) {",
				"  const key = process.env.CIPHER_KEY!;",
				"  return createCipheriv('aes-256-cbc', key, randomBytes(16));",
				"}",
			].join("\n"),
		);
		try {
			const result = await scan({ paths: [file], cwd: tempDir });
			expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(0);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("CS-ENC-01-30 let key reassigned before cipheriv still flags CS-ENC-01 on hardcoded init", async () => {
		const tempDir = fs.mkdtempSync(
			path.join(os.tmpdir(), "ciphersins-enc01-reassign-"),
		);
		const file = path.join(tempDir, "reassign-key.ts");
		fs.writeFileSync(
			file,
			[
				'import { createCipheriv, randomBytes } from "crypto";',
				"export function enc(data: Buffer, runtimeKey: Buffer) {",
				"  let key = 'hardcoded-key-16b';",
				"  key = runtimeKey;",
				"  return createCipheriv('aes-256-cbc', key, randomBytes(16));",
				"}",
			].join("\n"),
		);
		try {
			const result = await scan({ paths: [file], cwd: tempDir });
			expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("CS-ENC-01-31 const key shorthand in options object flags CS-ENC-01", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "gcm-hardcoded-key-with-options.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.message).toBe(CS_ENC_01_MESSAGE);
	});

	it("CS-ENC-01-32 bad directory ENC-01 count is eight after const resolution", async () => {
		const result = await scan({ paths: [enc01BadDir], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(8);
	});

	it("CS-ENC-01-33 const iv and const key yield single CS-ENC-01 finding", async () => {
		const tempDir = fs.mkdtempSync(
			path.join(os.tmpdir(), "ciphersins-enc01-both-const-"),
		);
		const file = path.join(tempDir, "both-const.ts");
		fs.writeFileSync(
			file,
			[
				'import { createCipheriv } from "crypto";',
				"export function enc() {",
				"  const key = 'hardcoded-key-16b';",
				"  const iv = 'iv16bytes!!!!!!!';",
				"  return createCipheriv('aes-256-cbc', key, iv);",
				"}",
			].join("\n"),
		);
		try {
			const result = await scan({ paths: [file], cwd: tempDir });
			expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});
});

describe("CS-ENC-01 isolated rule run", () => {
	it("CS-ENC-01-23 csEnc01Rule.run matches scan for cipheriv-hardcoded-key.ts", async () => {
		const file = fixturePath("bad", "cipheriv-hardcoded-key.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const context = createRuleContext(file);
		const findings = csEnc01Rule.run(context);

		expect(findings).toHaveLength(1);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});

	it("CS-ENC-01-24 csEnc01Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [enc01BadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csEnc01Rule.run(createRuleContext(file)),
		);

		const scanSigs = filterByRule(scanResult.findings, "CS-ENC-01")
			.map(findingSignature)
			.sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});
});

describe("CS-ENC-01 CLI", () => {
	it("CS-ENC-01-25 CLI scan of bad fixtures prints CS-ENC-01", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", enc01BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-ENC-01");
		expect(result.stdout).toMatch(
			/fixtures\/cs-enc-01\/bad\/[\w.-]+:\d+:\d+\s+CS-ENC-01\s+medium/,
		);
	});
});
