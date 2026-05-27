import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	allRules,
	createRuleContext,
	csJwt01Rule,
	parseSourceFile,
	scan,
} from "@ciphersins/core";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const jwtBadDir = path.join(rootDir, "fixtures/cs-jwt-01/bad");
const jwtGoodDir = path.join(rootDir, "fixtures/cs-jwt-01/good");
const cliEntry = path.join(rootDir, "packages/cli/dist/cli.js");

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-jwt-01", segment, name);
}

function normalizeFinding(finding: {
	ruleId: string;
	message: string;
	file: string;
	line: number;
	column: number;
	severity: string;
	snippet?: string;
	helpUrl?: string;
}) {
	return {
		ruleId: finding.ruleId,
		message: finding.message,
		severity: finding.severity,
		line: finding.line,
		column: finding.column,
		snippet: finding.snippet,
		helpUrl: finding.helpUrl,
		file: path.basename(finding.file),
	};
}

describe("CS-JWT-01 rule registry", () => {
	it("CS-JWT-01-01 registers CS-JWT-01 in allRules", () => {
		expect(allRules.some((rule) => rule.id === "CS-JWT-01")).toBe(true);
	});
});

describe("CS-JWT-01 directory scans", () => {
	it("CS-JWT-01-02 flags bad fixtures with high severity", async () => {
		const result = await scan({ paths: [jwtBadDir], cwd: rootDir });

		expect(result.findings.length).toBeGreaterThan(0);
		expect(result.findings.every((f) => f.ruleId === "CS-JWT-01")).toBe(true);
		expect(result.findings.every((f) => f.severity === "high")).toBe(true);
	});

	it("CS-JWT-01-03 reports no findings for good fixtures", async () => {
		const result = await scan({ paths: [jwtGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});
});

describe("CS-JWT-01 per-file bad fixtures", () => {
	it("CS-JWT-01-04 default-import-decode-only.ts yields exactly one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "default-import-decode-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
	});

	it("CS-JWT-01-05 multiple-decode-no-verify.ts yields exactly two findings", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "multiple-decode-no-verify.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(2);
	});

	it("CS-JWT-01-12 require-decode-only.js yields at least one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "require-decode-only.js")],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
	});

	it("CS-JWT-01-13 named-import-decode-alias.ts yields at least one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "named-import-decode-alias.ts")],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
	});

	it("CS-JWT-01-14 inline-require-decode-only.js yields at least one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "inline-require-decode-only.js")],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
	});

	it("CS-JWT-01-15 decode-only-with-type-annotation.ts yields at least one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-only-with-type-annotation.ts")],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
	});

	it("CS-JWT-01-16 decode-via-local-wrapper.ts yields at least one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-via-local-wrapper.ts")],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
	});

	it("CS-JWT-01-17 decode-in-component.tsx yields at least one finding", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "decode-in-component.tsx")],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
	});
});

describe("CS-JWT-01 per-file good fixtures", () => {
	it("CS-JWT-01-06 decode-and-verify-default.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "decode-and-verify-default.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-07 decode-and-verify-separated-functions.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "decode-and-verify-separated-functions.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-08 no-jsonwebtoken.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "no-jsonwebtoken.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-09 decode-in-string-literal.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "decode-in-string-literal.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-JWT-01-18 verify-in-dead-code-unreachable.ts yields no findings", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-in-dead-code-unreachable.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});

describe("CS-JWT-01 finding shape", () => {
	it("CS-JWT-01-10 finding snippet contains decode", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "default-import-decode-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.snippet).toContain("decode");
	});

	it("CS-JWT-01-11 finding helpUrl points to rule doc", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "default-import-decode-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings[0]?.helpUrl).toMatch(/docs\/rules\/CS-JWT-01\.md$/);
	});

	it("CS-JWT-01-19 summary.high equals finding count for bad directory", async () => {
		const result = await scan({ paths: [jwtBadDir], cwd: rootDir });

		expect(result.summary.high).toBe(result.findings.length);
	});

	it("CS-JWT-01-20 finding line and column point at decode call", async () => {
		const file = fixturePath("bad", "default-import-decode-only.ts");
		const result = await scan({ paths: [file], cwd: rootDir });
		const finding = result.findings[0];

		expect(finding).toBeDefined();
		expect(finding!.line).toBeGreaterThanOrEqual(1);
		expect(finding!.column).toBeGreaterThanOrEqual(1);

		const sourceFile = parseSourceFile(file);
		const lineText = sourceFile.getFullText().split("\n")[finding!.line - 1];
		expect(lineText).toContain("decode");
	});

	it("CS-JWT-01-22 golden snapshot for default-import-decode-only.ts", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "default-import-decode-only.ts")],
			cwd: rootDir,
		});

		expect(result.findings).toHaveLength(1);
		expect(normalizeFinding(result.findings[0]!)).toMatchSnapshot();
	});
});

describe("CS-JWT-01 isolated rule run", () => {
	it("CS-JWT-01-21 csJwt01Rule.run matches scan for single bad file", () => {
		const file = fixturePath("bad", "default-import-decode-only.ts");
		const context = createRuleContext(file);
		const findings = csJwt01Rule.run(context);

		expect(findings).toHaveLength(1);
		expect(findings[0]?.ruleId).toBe("CS-JWT-01");
	});
});

describe("CS-JWT-01 CLI", () => {
	it("CS-JWT-01-23 CLI scan of bad fixtures prints CS-JWT-01", () => {
		expect(fs.existsSync(cliEntry)).toBe(true);

		const result = spawnSync(process.execPath, [cliEntry, "scan", jwtBadDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("CS-JWT-01");
	});

	it("CS-JWT-01-24 CLI scan of good fixtures prints No findings.", () => {
		const result = spawnSync(process.execPath, [cliEntry, "scan", jwtGoodDir], {
			encoding: "utf8",
			cwd: rootDir,
		});

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("No findings.");
	});
});
