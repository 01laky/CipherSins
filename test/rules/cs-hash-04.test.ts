import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csHash04Rule,
	scan,
	SCRYPT_MIN_BLOCK_SIZE,
	SCRYPT_MIN_COST,
	SCRYPT_MIN_PARALLELIZATION,
} from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const hash04BadDir = path.join(rootDir, "fixtures/cs-hash-04/bad");
const hash04GoodDir = path.join(rootDir, "fixtures/cs-hash-04/good");
const hash01GoodDir = path.join(rootDir, "fixtures/cs-hash-01/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const CS_HASH_04_MESSAGE = `scrypt parameters below minimum (cost ≥ ${SCRYPT_MIN_COST}, blockSize ≥ ${SCRYPT_MIN_BLOCK_SIZE}, parallelization ≥ ${SCRYPT_MIN_PARALLELIZATION}) in password context; increase scrypt cost or use stronger KDF settings.`;

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-hash-04", segment, name);
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

describe("CS-HASH-04 rule registry", () => {
	it("CS-HASH-04-01 registers CS-HASH-04 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-HASH-04")).toBe(true);
	});

	it("CS-HASH-04-02 csHash04Rule metadata matches rule spec", () => {
		expect(csHash04Rule.id).toBe("CS-HASH-04");
		expect(csHash04Rule.title).toBe("scrypt cost factor too low");
		expect(csHash04Rule.severity).toBe("medium");
	});

	it("CS-HASH-04-03 csHash04Rule is registered at index 12 after CS-HASH-03", () => {
		expect(allRules[12]).toBe(csHash04Rule);
		expect(allRules.find((rule) => rule.id === "CS-HASH-04")).toBe(
			csHash04Rule,
		);
	});

	it("CS-HASH-04-04 exported SCRYPT_MIN_COST is 16384", () => {
		expect(SCRYPT_MIN_COST).toBe(16_384);
	});

	it("CS-HASH-04-05 exported SCRYPT_MIN_BLOCK_SIZE is 8", () => {
		expect(SCRYPT_MIN_BLOCK_SIZE).toBe(8);
	});

	it("CS-HASH-04-06 exported SCRYPT_MIN_PARALLELIZATION is 1", () => {
		expect(SCRYPT_MIN_PARALLELIZATION).toBe(1);
	});
});

describe("CS-HASH-04 directory scans", () => {
	it("CS-HASH-04-07 flags bad fixtures with medium severity", async () => {
		const result = await scan({ paths: [hash04BadDir], cwd: rootDir });
		const hash04Findings = filterByRule(result.findings, "CS-HASH-04");

		expect(hash04Findings).toHaveLength(5);
		expect(result.scannedFiles).toHaveLength(5);
		expect(hash04Findings.every((f) => f.severity === "medium")).toBe(true);
		expect(hash04Findings.every((f) => f.message === CS_HASH_04_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-HASH-04-08 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [hash04GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-HASH-04 per-file bad fixtures", () => {
	it("CS-HASH-04-09 scrypt-low-cost.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "scrypt-low-cost.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(1);
	});

	it("CS-HASH-04-10 scrypt-low-blocksize.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "scrypt-low-blocksize.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(1);
	});

	it("CS-HASH-04-11 scrypt-low-parallelization.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "scrypt-low-parallelization.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(1);
	});

	it("CS-HASH-04-12 scrypt-async-low.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "scrypt-async-low.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(1);
	});

	it("CS-HASH-04-13 scrypt-variable-cost.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "scrypt-variable-cost.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(1);
	});
});

describe("CS-HASH-04 per-file good fixtures", () => {
	it("CS-HASH-04-14 scrypt-explicit-16384.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "scrypt-explicit-16384.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-04-15 scrypt-default-no-options.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "scrypt-default-no-options.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-04-16 scrypt-async-callback-only.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "scrypt-async-callback-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-04-17 scrypt-indirect-config.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "scrypt-indirect-config.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-04-18 scrypt-no-password-context.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "scrypt-no-password-context.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-04-19 bcrypt-only.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "bcrypt-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-HASH-04 cross-rule overlap", () => {
	it("CS-HASH-04-INT-01 scrypt-password.ts in hash-01 good yields zero HASH-04", async () => {
		const file = path.join(hash01GoodDir, "scrypt-password.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(0);
	});
});

describe("CS-HASH-04 finding shape and isolation", () => {
	it("CS-HASH-04-20 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "scrypt-low-cost.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-HASH-04\.md$/);
	});

	it("CS-HASH-04-21 summary.medium equals CS-HASH-04 finding count for bad directory", async () => {
		const result = await scan({ paths: [hash04BadDir], cwd: rootDir });
		const hash04Findings = filterByRule(result.findings, "CS-HASH-04");

		expect(result.summary.medium).toBeGreaterThanOrEqual(hash04Findings.length);
		expect(hash04Findings).toHaveLength(5);
	});

	it("CS-HASH-04-22 csHash04Rule.run matches scan for scrypt-low-cost.ts", async () => {
		const file = fixturePath("bad", "scrypt-low-cost.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const findings = csHash04Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});

	it("CS-HASH-04-23 csHash04Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [hash04BadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csHash04Rule.run(createRuleContext(file)),
		);

		const scanSigs = filterByRule(scanResult.findings, "CS-HASH-04")
			.map(findingSignature)
			.sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});
});

describe("CS-HASH-04 CLI", () => {
	it("CS-HASH-04-24 CLI scan of bad fixtures prints CS-HASH-04", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", hash04BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-HASH-04");
	});
});

describe("CS-HASH-04 edge cases", () => {
	it("CS-HASH-04-25 scrypt at exact minimum cost stays clean", async () => {
		const file = fixturePath("good", "scrypt-explicit-16384.ts");
		const result = await scan({ paths: [file], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-HASH-04")).toHaveLength(0);
	});

	it("CS-HASH-04-26 bad directory hits only CS-HASH-04 rule id", async () => {
		const result = await scan({ paths: [hash04BadDir], cwd: rootDir });
		const ruleIds = new Set(result.findings.map((f) => f.ruleId));

		expect([...ruleIds]).toEqual(["CS-HASH-04"]);
	});

	it("CS-HASH-04-27 good directory scans six files with zero findings", async () => {
		const result = await scan({ paths: [hash04GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(6);
		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-04-28 scrypt-low-cost finding severity is medium not high", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "scrypt-low-cost.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.severity).toBe("medium");
	});
});
