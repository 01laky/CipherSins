import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csRng02Rule,
	RNG_MIN_AUTH_BYTES,
	scan,
} from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const rng02BadDir = path.join(rootDir, "fixtures/cs-rng-02/bad");
const rng02GoodDir = path.join(rootDir, "fixtures/cs-rng-02/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const CS_RNG_02_MESSAGE = `crypto.randomBytes(n) with n below ${RNG_MIN_AUTH_BYTES} in auth-related context; use at least ${RNG_MIN_AUTH_BYTES} bytes for tokens and secrets.`;

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-rng-02", segment, name);
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

describe("CS-RNG-02 rule registry", () => {
	it("CS-RNG-02-01 registers CS-RNG-02 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-RNG-02")).toBe(true);
	});

	it("CS-RNG-02-02 csRng02Rule metadata matches rule spec", () => {
		expect(csRng02Rule.id).toBe("CS-RNG-02");
		expect(csRng02Rule.title).toBe("randomBytes length too small");
		expect(csRng02Rule.severity).toBe("high");
	});

	it("CS-RNG-02-03 csRng02Rule is registered at index 8 after CS-RNG-01", () => {
		expect(allRules[8]).toBe(csRng02Rule);
	});

	it("CS-RNG-02-04 exported RNG_MIN_AUTH_BYTES is 16", () => {
		expect(RNG_MIN_AUTH_BYTES).toBe(16);
	});
});

describe("CS-RNG-02 directory scans", () => {
	it("CS-RNG-02-05 flags bad fixtures with high severity", async () => {
		const result = await scan({ paths: [rng02BadDir], cwd: rootDir });
		const rng02Findings = filterByRule(result.findings, "CS-RNG-02");

		expect(rng02Findings).toHaveLength(4);
		expect(result.scannedFiles).toHaveLength(4);
		expect(rng02Findings.every((f) => f.severity === "high")).toBe(true);
		expect(rng02Findings.every((f) => f.message === CS_RNG_02_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-RNG-02-06 reports no RNG-02 findings for good fixtures", async () => {
		const result = await scan({ paths: [rng02GoodDir], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(0);
	});
});

describe("CS-RNG-02 per-file bad fixtures", () => {
	it("CS-RNG-02-07 random-bytes-8-session.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "random-bytes-8-session.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(1);
	});

	it("CS-RNG-02-08 random-bytes-1-otp.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "random-bytes-1-otp.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(1);
	});

	it("CS-RNG-02-09 random-bytes-variable-literal.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "random-bytes-variable-literal.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(1);
	});

	it("CS-RNG-02-10 member-random-bytes-short.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "member-random-bytes-short.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(1);
	});
});

describe("CS-RNG-02 per-file good fixtures", () => {
	it("CS-RNG-02-11 random-bytes-16-token.ts yields no RNG-02 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "random-bytes-16-token.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(0);
	});

	it("CS-RNG-02-12 random-bytes-32-key.ts yields no RNG-02 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "random-bytes-32-key.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(0);
	});

	it("CS-RNG-02-13 random-bytes-short-no-auth.ts yields no RNG-02 findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "random-bytes-short-no-auth.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(0);
	});

	it("CS-RNG-02-14 math-random-auth.ts flags RNG-01 not RNG-02", async () => {
		const result = await scan({
			paths: [fixturePath("good", "math-random-auth.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-RNG-01")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-RNG-02")).toHaveLength(0);
	});
});

describe("CS-RNG-02 finding shape and isolation", () => {
	it("CS-RNG-02-15 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "random-bytes-8-session.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-RNG-02\.md$/);
	});

	it("CS-RNG-02-16 csRng02Rule.run matches scan for random-bytes-8-session.ts", async () => {
		const file = fixturePath("bad", "random-bytes-8-session.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const findings = csRng02Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});

	it("CS-RNG-02-17 csRng02Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [rng02BadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csRng02Rule.run(createRuleContext(file)),
		);

		const scanSigs = filterByRule(scanResult.findings, "CS-RNG-02")
			.map(findingSignature)
			.sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});
});

describe("CS-RNG-02 CLI", () => {
	it("CS-RNG-02-18 CLI scan of bad fixtures prints CS-RNG-02", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", rng02BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-RNG-02");
	});
});

describe("CS-RNG-02 edge cases", () => {
	it("CS-RNG-02-19 bad directory hits only CS-RNG-02 rule id", async () => {
		const result = await scan({ paths: [rng02BadDir], cwd: rootDir });
		const ruleIds = new Set(result.findings.map((f) => f.ruleId));

		expect([...ruleIds]).toEqual(["CS-RNG-02"]);
	});

	it("CS-RNG-02-20 good directory scans four files", async () => {
		const result = await scan({ paths: [rng02GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(4);
	});
});
