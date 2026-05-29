import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	ARGON2_MIN_MEMORY_COST,
	ARGON2_MIN_TIME_COST,
	createRuleContext,
	csHash05Rule,
	scan,
} from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const hash05BadDir = path.join(rootDir, "fixtures/cs-hash-05/bad");
const hash05GoodDir = path.join(rootDir, "fixtures/cs-hash-05/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const CS_HASH_05_MESSAGE = `argon2 timeCost or memoryCost below recommended minimum (timeCost ≥ ${ARGON2_MIN_TIME_COST}, memoryCost ≥ ${ARGON2_MIN_MEMORY_COST} KiB) in password context; increase argon2 parameters.`;

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-hash-05", segment, name);
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

describe("CS-HASH-05 rule registry", () => {
	it("CS-HASH-05-01 registers CS-HASH-05 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-HASH-05")).toBe(true);
	});

	it("CS-HASH-05-02 csHash05Rule metadata matches rule spec", () => {
		expect(csHash05Rule.id).toBe("CS-HASH-05");
		expect(csHash05Rule.title).toBe("argon2 parameters too low");
		expect(csHash05Rule.severity).toBe("medium");
	});

	it("CS-HASH-05-03 csHash05Rule is registered at index 13 after CS-HASH-04", () => {
		expect(allRules[13]).toBe(csHash05Rule);
	});

	it("CS-HASH-05-04 exported ARGON2_MIN_TIME_COST is 3", () => {
		expect(ARGON2_MIN_TIME_COST).toBe(3);
	});

	it("CS-HASH-05-05 exported ARGON2_MIN_MEMORY_COST is 65536", () => {
		expect(ARGON2_MIN_MEMORY_COST).toBe(65_536);
	});
});

describe("CS-HASH-05 directory scans", () => {
	it("CS-HASH-05-06 flags bad fixtures with medium severity", async () => {
		const result = await scan({ paths: [hash05BadDir], cwd: rootDir });
		const hash05Findings = filterByRule(result.findings, "CS-HASH-05");

		expect(hash05Findings).toHaveLength(5);
		expect(result.scannedFiles).toHaveLength(5);
		expect(hash05Findings.every((f) => f.severity === "medium")).toBe(true);
		expect(hash05Findings.every((f) => f.message === CS_HASH_05_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-HASH-05-07 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [hash05GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-HASH-05 per-file bad fixtures", () => {
	it("CS-HASH-05-08 argon2-low-timecost.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "argon2-low-timecost.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(1);
	});

	it("CS-HASH-05-09 argon2-low-memory.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "argon2-low-memory.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(1);
	});

	it("CS-HASH-05-10 argon2-sync-low.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "argon2-sync-low.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(1);
	});

	it("CS-HASH-05-11 argon2-variable-timecost.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "argon2-variable-timecost.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(1);
	});

	it("CS-HASH-05-12 node-rs-argon2-low.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "node-rs-argon2-low.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(1);
	});
});

describe("CS-HASH-05 per-file good fixtures", () => {
	it("CS-HASH-05-13 argon2-above-min.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "argon2-above-min.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-05-14 argon2-recommended.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "argon2-recommended.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-05-15 argon2-indirect-config.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "argon2-indirect-config.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-05-16 argon2-low-no-password-context.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "argon2-low-no-password-context.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-05-17 bcrypt-only.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "bcrypt-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-HASH-05 cross-rule overlap", () => {
	it("CS-HASH-05-INT-01 argon2-low-timecost.ts yields exactly one HASH-05", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "argon2-low-timecost.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-HASH-05")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-HASH-01")).toHaveLength(0);
	});
});

describe("CS-HASH-05 finding shape and isolation", () => {
	it("CS-HASH-05-18 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "argon2-low-timecost.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-HASH-05\.md$/);
	});

	it("CS-HASH-05-19 csHash05Rule.run matches scan for argon2-low-timecost.ts", async () => {
		const file = fixturePath("bad", "argon2-low-timecost.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const findings = csHash05Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});

	it("CS-HASH-05-20 csHash05Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [hash05BadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csHash05Rule.run(createRuleContext(file)),
		);

		const scanSigs = filterByRule(scanResult.findings, "CS-HASH-05")
			.map(findingSignature)
			.sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});
});

describe("CS-HASH-05 CLI", () => {
	it("CS-HASH-05-21 CLI scan of bad fixtures prints CS-HASH-05", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", hash05BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-HASH-05");
	});
});

describe("CS-HASH-05 edge cases", () => {
	it("CS-HASH-05-22 bad directory hits only CS-HASH-05 rule id", async () => {
		const result = await scan({ paths: [hash05BadDir], cwd: rootDir });
		const ruleIds = new Set(result.findings.map((f) => f.ruleId));

		expect([...ruleIds]).toEqual(["CS-HASH-05"]);
	});

	it("CS-HASH-05-23 good directory scans five files with zero findings", async () => {
		const result = await scan({ paths: [hash05GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(5);
		expect(result.findings).toEqual([]);
	});

	it("CS-HASH-05-24 argon2-low-timecost finding severity is medium", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "argon2-low-timecost.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.severity).toBe("medium");
	});
});
