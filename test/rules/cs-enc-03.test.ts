import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allRules, createRuleContext, csEnc03Rule, scan } from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const enc03BadDir = path.join(rootDir, "fixtures/cs-enc-03/bad");
const enc03GoodDir = path.join(rootDir, "fixtures/cs-enc-03/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const CS_ENC_03_MESSAGE =
	"Weak or deprecated cipher algorithm passed to createCipheriv/createDecipheriv; use AES-GCM or another modern algorithm.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-enc-03", segment, name);
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

describe("CS-ENC-03 rule registry", () => {
	it("CS-ENC-03-01 registers CS-ENC-03 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-ENC-03")).toBe(true);
	});

	it("CS-ENC-03-02 csEnc03Rule metadata matches rule spec", () => {
		expect(csEnc03Rule.id).toBe("CS-ENC-03");
		expect(csEnc03Rule.title).toBe("Weak or deprecated cipher algorithm");
		expect(csEnc03Rule.severity).toBe("high");
	});

	it("CS-ENC-03-03 csEnc03Rule is registered at index 16 after CS-ENC-02", () => {
		expect(allRules[16]).toBe(csEnc03Rule);
	});
});

describe("CS-ENC-03 directory scans", () => {
	it("CS-ENC-03-04 flags bad fixtures with high severity", async () => {
		const result = await scan({ paths: [enc03BadDir], cwd: rootDir });
		const enc03Findings = filterByRule(result.findings, "CS-ENC-03");

		expect(enc03Findings).toHaveLength(5);
		expect(result.scannedFiles).toHaveLength(5);
		expect(enc03Findings.every((f) => f.severity === "high")).toBe(true);
		expect(enc03Findings.every((f) => f.message === CS_ENC_03_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-ENC-03-05 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [enc03GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-ENC-03 per-file bad fixtures", () => {
	it("CS-ENC-03-06 bf-cipheriv.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "bf-cipheriv.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-03")).toHaveLength(1);
	});

	it("CS-ENC-03-07 rc4-cipheriv.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "rc4-cipheriv.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-03")).toHaveLength(1);
	});

	it("CS-ENC-03-08 des-cbc-cipheriv.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "des-cbc-cipheriv.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-03")).toHaveLength(1);
	});

	it("CS-ENC-03-09 cast5-decipheriv.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "cast5-decipheriv.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-03")).toHaveLength(1);
	});

	it("CS-ENC-03-10 des-hardcoded-key.ts yields ENC-01 and ENC-03", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "des-hardcoded-key.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-03")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-ENC-01")).toHaveLength(1);
	});
});

describe("CS-ENC-03 per-file good fixtures", () => {
	it("CS-ENC-03-11 aes-256-gcm.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "aes-256-gcm.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-03-12 aes-256-cbc.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "aes-256-cbc.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-03-13 chacha20-poly1305.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "chacha20-poly1305.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-03-14 variable-algorithm.ts yields no ENC-03 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "variable-algorithm.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-03")).toHaveLength(0);
	});

	it("CS-ENC-03-15 node-crypto-aes.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "node-crypto-aes.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-ENC-03 finding shape and isolation", () => {
	it("CS-ENC-03-16 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "bf-cipheriv.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-ENC-03\.md$/);
	});

	it("CS-ENC-03-17 csEnc03Rule.run matches scan for bf-cipheriv.ts", async () => {
		const file = fixturePath("bad", "bf-cipheriv.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const findings = csEnc03Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});

	it("CS-ENC-03-18 csEnc03Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [enc03BadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csEnc03Rule.run(createRuleContext(file)),
		);

		const scanSigs = filterByRule(scanResult.findings, "CS-ENC-03")
			.map(findingSignature)
			.sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});
});

describe("CS-ENC-03 CLI", () => {
	it("CS-ENC-03-19 CLI scan of bad fixtures prints CS-ENC-03", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", enc03BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-ENC-03");
	});
});

describe("CS-ENC-03 edge cases", () => {
	it("CS-ENC-03-20 good directory scans five files with zero findings", async () => {
		const result = await scan({ paths: [enc03GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(5);
		expect(result.findings).toEqual([]);
	});
});
