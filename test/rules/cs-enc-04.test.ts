import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allRules, createRuleContext, csEnc04Rule, scan } from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const enc04BadDir = path.join(rootDir, "fixtures/cs-enc-04/bad");
const enc04GoodDir = path.join(rootDir, "fixtures/cs-enc-04/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const CS_ENC_04_MESSAGE =
	"ECB mode cipher (algorithm ending with -ecb); use a mode with proper IV handling such as GCM or CBC.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-enc-04", segment, name);
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

describe("CS-ENC-04 rule registry", () => {
	it("CS-ENC-04-01 registers CS-ENC-04 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-ENC-04")).toBe(true);
	});

	it("CS-ENC-04-02 csEnc04Rule metadata matches rule spec", () => {
		expect(csEnc04Rule.id).toBe("CS-ENC-04");
		expect(csEnc04Rule.title).toBe("ECB mode cipher");
		expect(csEnc04Rule.severity).toBe("high");
	});

	it("CS-ENC-04-03 csEnc04Rule is registered at index 17 after CS-ENC-03", () => {
		expect(allRules[17]).toBe(csEnc04Rule);
	});
});

describe("CS-ENC-04 directory scans", () => {
	it("CS-ENC-04-04 flags bad fixtures with high severity", async () => {
		const result = await scan({ paths: [enc04BadDir], cwd: rootDir });
		const enc04Findings = filterByRule(result.findings, "CS-ENC-04");

		expect(enc04Findings).toHaveLength(4);
		expect(result.scannedFiles).toHaveLength(4);
		expect(enc04Findings.every((f) => f.severity === "high")).toBe(true);
		expect(enc04Findings.every((f) => f.message === CS_ENC_04_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-ENC-04-05 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [enc04GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-ENC-04 per-file bad fixtures", () => {
	it("CS-ENC-04-06 aes-128-ecb-cipheriv.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "aes-128-ecb-cipheriv.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-04")).toHaveLength(1);
	});

	it("CS-ENC-04-07 aes-256-ecb-decipheriv.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "aes-256-ecb-decipheriv.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-04")).toHaveLength(1);
	});

	it("CS-ENC-04-08 node-crypto-ecb.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "node-crypto-ecb.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-04")).toHaveLength(1);
	});

	it("CS-ENC-04-09 ecb-require.js yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "ecb-require.js")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-04")).toHaveLength(1);
	});
});

describe("CS-ENC-04 per-file good fixtures", () => {
	it("CS-ENC-04-10 aes-256-cbc.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "aes-256-cbc.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-04-11 aes-256-gcm.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "aes-256-gcm.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-ENC-04-12 variable-algorithm.ts yields no ENC-04 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "variable-algorithm.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-ENC-04")).toHaveLength(0);
	});
});

describe("CS-ENC-04 finding shape and isolation", () => {
	it("CS-ENC-04-13 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "aes-128-ecb-cipheriv.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-ENC-04\.md$/);
	});

	it("CS-ENC-04-14 csEnc04Rule.run matches scan for aes-128-ecb-cipheriv.ts", async () => {
		const file = fixturePath("bad", "aes-128-ecb-cipheriv.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const findings = csEnc04Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});

	it("CS-ENC-04-15 csEnc04Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [enc04BadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csEnc04Rule.run(createRuleContext(file)),
		);

		const scanSigs = filterByRule(scanResult.findings, "CS-ENC-04")
			.map(findingSignature)
			.sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});
});

describe("CS-ENC-04 CLI", () => {
	it("CS-ENC-04-16 CLI scan of bad fixtures prints CS-ENC-04", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", enc04BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-ENC-04");
	});
});

describe("CS-ENC-04 edge cases", () => {
	it("CS-ENC-04-17 bad directory hits only CS-ENC-04 rule id", async () => {
		const result = await scan({ paths: [enc04BadDir], cwd: rootDir });
		const ruleIds = new Set(result.findings.map((f) => f.ruleId));

		expect([...ruleIds]).toEqual(["CS-ENC-04"]);
	});

	it("CS-ENC-04-18 good directory scans three files with zero findings", async () => {
		const result = await scan({ paths: [enc04GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(3);
		expect(result.findings).toEqual([]);
	});
});
