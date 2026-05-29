import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allRules, createRuleContext, csJwt05Rule, scan } from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const jwt05BadDir = path.join(rootDir, "fixtures/cs-jwt-05/bad");
const jwt05GoodDir = path.join(rootDir, "fixtures/cs-jwt-05/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const CS_JWT_05_MESSAGE =
	"jwt.sign() without expiresIn or exp claim; tokens may never expire.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-jwt-05", segment, name);
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

describe("CS-JWT-05 rule registry", () => {
	it("CS-JWT-05-01 registers CS-JWT-05 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-JWT-05")).toBe(true);
	});

	it("CS-JWT-05-02 csJwt05Rule metadata matches rule spec", () => {
		expect(csJwt05Rule.id).toBe("CS-JWT-05");
		expect(csJwt05Rule.title).toBe("JWT sign without expiry");
		expect(csJwt05Rule.severity).toBe("medium");
	});

	it("CS-JWT-05-03 csJwt05Rule is registered at index 4 after CS-JWT-04", () => {
		expect(allRules[4]).toBe(csJwt05Rule);
	});
});

describe("CS-JWT-05 directory scans", () => {
	it("CS-JWT-05-04 flags bad fixtures with medium severity", async () => {
		const result = await scan({ paths: [jwt05BadDir], cwd: rootDir });
		const jwt05Findings = filterByRule(result.findings, "CS-JWT-05");

		expect(jwt05Findings).toHaveLength(5);
		expect(result.scannedFiles).toHaveLength(5);
		expect(jwt05Findings.every((f) => f.severity === "medium")).toBe(true);
		expect(jwt05Findings.every((f) => f.message === CS_JWT_05_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-JWT-05-05 bad directory also includes one CS-JWT-03 from sign-none-and-no-expiry", async () => {
		const result = await scan({ paths: [jwt05BadDir], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
		expect(result.findings).toHaveLength(6);
	});

	it("CS-JWT-05-06 reports no JWT-05 findings for good fixtures", async () => {
		const result = await scan({ paths: [jwt05GoodDir], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(0);
	});
});

describe("CS-JWT-05 per-file bad fixtures", () => {
	it("CS-JWT-05-07 sign-no-expiry.ts yields exactly one JWT-05 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-no-expiry.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
	});

	it("CS-JWT-05-08 sign-empty-options.ts yields exactly one JWT-05 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-empty-options.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
	});

	it("CS-JWT-05-09 sign-nbf-only.ts yields exactly one JWT-05 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-nbf-only.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
	});

	it("CS-JWT-05-10 sign-callback-no-expiry.ts yields exactly one JWT-05 finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-callback-no-expiry.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
	});

	it("CS-JWT-05-11 sign-none-and-no-expiry.ts yields JWT-03 and JWT-05", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-none-and-no-expiry.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-03")).toHaveLength(1);
	});
});

describe("CS-JWT-05 per-file good fixtures", () => {
	it("CS-JWT-05-12 sign-expires-in.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sign-expires-in.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-05-13 sign-exp-claim.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sign-exp-claim.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-05-14 sign-bound-expires-in.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sign-bound-expires-in.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-05-15 sign-expires-in-callback.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sign-expires-in-callback.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-05-16 verify-only.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-JWT-05 finding shape and isolation", () => {
	it("CS-JWT-05-17 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-no-expiry.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-JWT-05\.md$/);
	});

	it("CS-JWT-05-18 csJwt05Rule.run matches scan for sign-no-expiry.ts", async () => {
		const file = fixturePath("bad", "sign-no-expiry.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const findings = csJwt05Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		expect(findingSignature(findings[0]!)).toBe(
			findingSignature(scanResult.findings[0]!),
		);
	});

	it("CS-JWT-05-19 csJwt05Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [jwt05BadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csJwt05Rule.run(createRuleContext(file)),
		);

		const scanSigs = filterByRule(scanResult.findings, "CS-JWT-05")
			.map(findingSignature)
			.sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});
});

describe("CS-JWT-05 CLI", () => {
	it("CS-JWT-05-20 CLI scan of bad fixtures prints CS-JWT-05", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", jwt05BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-JWT-05");
	});
});

describe("CS-JWT-05 edge cases", () => {
	it("CS-JWT-05-21 good directory scans five files with zero findings", async () => {
		const result = await scan({ paths: [jwt05GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(5);
		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-05-22 sign-no-expiry finding severity is medium not high", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-no-expiry.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.severity).toBe("medium");
	});

	it("CS-JWT-05-23 bad directory JWT-05 count is five excluding JWT-03 overlap", async () => {
		const result = await scan({ paths: [jwt05BadDir], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(5);
	});

	it("CS-JWT-05-24 sign-no-expiry snippet contains jwt.sign", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-no-expiry.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.snippet).toContain("jwt.sign");
	});

	it("CS-JWT-05-25 entire jwt-05 good directory stays clean with nineteen rules", async () => {
		const result = await scan({ paths: [jwt05GoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});
