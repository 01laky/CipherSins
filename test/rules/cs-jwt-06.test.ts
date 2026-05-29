import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { allRules, createRuleContext, csJwt06Rule, scan } from "ciphersins";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const jwt06BadDir = path.join(rootDir, "fixtures/cs-jwt-06/bad");
const jwt06GoodDir = path.join(rootDir, "fixtures/cs-jwt-06/good");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const CS_JWT_06_MESSAGE =
	"jwt.sign() with noTimestamp: true but no expiresIn or exp; token may lack time bounds.";

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-jwt-06", segment, name);
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

describe("CS-JWT-06 rule registry", () => {
	it("CS-JWT-06-01 registers CS-JWT-06 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-JWT-06")).toBe(true);
	});

	it("CS-JWT-06-02 csJwt06Rule metadata matches rule spec", () => {
		expect(csJwt06Rule.id).toBe("CS-JWT-06");
		expect(csJwt06Rule.title).toBe("JWT sign with noTimestamp");
		expect(csJwt06Rule.severity).toBe("medium");
	});

	it("CS-JWT-06-03 csJwt06Rule is registered at index 5 after CS-JWT-05", () => {
		expect(allRules[5]).toBe(csJwt06Rule);
	});
});

describe("CS-JWT-06 directory scans", () => {
	it("CS-JWT-06-04 flags bad fixtures with medium severity", async () => {
		const result = await scan({ paths: [jwt06BadDir], cwd: rootDir });
		const jwt06Findings = filterByRule(result.findings, "CS-JWT-06");

		expect(jwt06Findings).toHaveLength(3);
		expect(result.scannedFiles).toHaveLength(3);
		expect(jwt06Findings.every((f) => f.severity === "medium")).toBe(true);
		expect(jwt06Findings.every((f) => f.message === CS_JWT_06_MESSAGE)).toBe(
			true,
		);
	});

	it("CS-JWT-06-05 bad directory also includes three CS-JWT-05 overlap findings", async () => {
		const result = await scan({ paths: [jwt06BadDir], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(3);
		expect(result.findings).toHaveLength(6);
	});

	it("CS-JWT-06-06 reports no JWT-06 findings for good fixtures", async () => {
		const result = await scan({ paths: [jwt06GoodDir], cwd: rootDir });

		expect(filterByRule(result.findings, "CS-JWT-06")).toHaveLength(0);
	});
});

describe("CS-JWT-06 per-file bad fixtures", () => {
	it("CS-JWT-06-07 sign-no-timestamp-no-expiry.ts yields JWT-05 and JWT-06", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-no-timestamp-no-expiry.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-06")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
	});

	it("CS-JWT-06-08 sign-no-timestamp-empty-payload.ts yields JWT-05 and JWT-06", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-no-timestamp-empty-payload.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-06")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
	});

	it("CS-JWT-06-09 sign-no-timestamp-alias.ts yields JWT-05 and JWT-06", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-no-timestamp-alias.ts")],
			cwd: rootDir,
		});

		expect(filterByRule(result.findings, "CS-JWT-06")).toHaveLength(1);
		expect(filterByRule(result.findings, "CS-JWT-05")).toHaveLength(1);
	});
});

describe("CS-JWT-06 per-file good fixtures", () => {
	it("CS-JWT-06-10 sign-no-timestamp-with-expires.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sign-no-timestamp-with-expires.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-06-11 sign-no-timestamp-with-exp-claim.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sign-no-timestamp-with-exp-claim.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-06-12 sign-normal-expires.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "sign-normal-expires.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-JWT-06 finding shape and isolation", () => {
	it("CS-JWT-06-13 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-no-timestamp-no-expiry.ts")],
			cwd: rootDir,
		});
		const jwt06Finding = filterByRule(result.findings, "CS-JWT-06")[0];

		expect(jwt06Finding?.helpUrl).toMatch(/docs\/rules\/CS-JWT-06\.md$/);
	});

	it("CS-JWT-06-14 csJwt06Rule.run matches scan for sign-no-timestamp-no-expiry.ts", async () => {
		const file = fixturePath("bad", "sign-no-timestamp-no-expiry.ts");
		const scanResult = await scan({ paths: [file], cwd: rootDir });
		const findings = csJwt06Rule.run(createRuleContext(file));

		expect(findings).toHaveLength(1);
		const scanJwt06 = filterByRule(scanResult.findings, "CS-JWT-06")[0]!;
		expect(findingSignature(findings[0]!)).toBe(findingSignature(scanJwt06));
	});

	it("CS-JWT-06-15 csJwt06Rule.run matches scan for entire bad directory", async () => {
		const scanResult = await scan({ paths: [jwt06BadDir], cwd: rootDir });
		const isolatedFindings = scanResult.scannedFiles.flatMap((file) =>
			csJwt06Rule.run(createRuleContext(file)),
		);

		const scanSigs = filterByRule(scanResult.findings, "CS-JWT-06")
			.map(findingSignature)
			.sort();
		const isolatedSigs = isolatedFindings.map(findingSignature).sort();

		expect(isolatedSigs).toEqual(scanSigs);
	});
});

describe("CS-JWT-06 CLI", () => {
	it("CS-JWT-06-16 CLI scan of bad fixtures prints CS-JWT-06", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(
			process.execPath,
			[cliEntry, "scan", jwt06BadDir],
			{
				encoding: "utf8",
				cwd: rootDir,
			},
		);

		expect(result.status).toBe(0);
		expect(result.stderr).toBe("");
		expect(result.stdout).toContain("CS-JWT-06");
	});
});

describe("CS-JWT-06 edge cases", () => {
	it("CS-JWT-06-17 good directory scans three files with zero findings", async () => {
		const result = await scan({ paths: [jwt06GoodDir], cwd: rootDir });

		expect(result.scannedFiles).toHaveLength(3);
		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-06-18 sign-no-timestamp-no-expiry finding severity is medium", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "sign-no-timestamp-no-expiry.ts")],
			cwd: rootDir,
		});
		const jwt06Finding = filterByRule(result.findings, "CS-JWT-06")[0];

		expect(jwt06Finding?.severity).toBe("medium");
	});
});
