import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	buildStepSummaryMarkdown,
	formatOneLineSummary,
	parseScanOutputFile,
	parseSummaryFromJson,
	parseSummaryFromSarif,
} from "../../.github/actions/scan/summary.mjs";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");
const actionYml = path.join(rootDir, ".github/actions/scan/action.yml");
const runSh = path.join(rootDir, ".github/actions/scan/run.sh");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

function readActionYml(): string {
	return fs.readFileSync(actionYml, "utf8");
}

describe("CS-ACT GitHub Action", () => {
	it("CS-ACT-01 action.yml exists with required inputs", () => {
		expect(fs.existsSync(actionYml)).toBe(true);
		const source = readActionYml();
		for (const input of [
			"path:",
			"version:",
			"fail-on:",
			"format:",
			"upload-sarif:",
			"sarif-category:",
			"soft-fail:",
			"cache-npm:",
			"write-summary:",
			"scan-title:",
		]) {
			expect(source).toContain(input);
		}
		expect(source).toContain("runs:");
		expect(source).toContain("using: composite");
	});

	it("CS-ACT-02 action references npx ciphersins or workspace CLI via run.sh", () => {
		const runSource = fs.readFileSync(runSh, "utf8");
		expect(runSource).toMatch(/npx --yes "ciphersins@/);
		expect(runSource).toContain("packages/ciphersins/dist/cli.js");
		expect(readActionYml()).toContain("run.sh");
	});

	it("CS-ACT-03 Action defaults are CI opinionated in action.yml", () => {
		const source = readActionYml();
		expect(source).toMatch(/fail-on:[\s\S]*default: "high"/);
		expect(source).toMatch(/format:[\s\S]*default: "sarif"/);
		expect(source).toMatch(/no-color:[\s\S]*default: "true"/);
	});

	it("CS-ACT-04 run.sh resolves ./src when directory exists", () => {
		const runSource = fs.readFileSync(runSh, "utf8");
		expect(runSource).toContain("resolve_default_path");
		expect(runSource).toContain('[ -d "$base/src" ]');
	});

	it("CS-ACT-05 soft-fail logic allows exit 1 without failing", () => {
		const runSource = fs.readFileSync(runSh, "utf8");
		expect(runSource).toContain("INPUT_SOFT_FAIL");
		expect(runSource).toContain('EXIT_CODE" -eq 1');
		expect(runSource).toContain('INPUT_SOFT_FAIL" != "true"');
	});

	it("CS-ACT-06 summary.mjs parses JSON and SARIF counts", () => {
		const jsonCounts = parseSummaryFromJson({
			summary: { critical: 0, high: 1, medium: 2, low: 0 },
		});
		expect(jsonCounts).toEqual({
			total: 3,
			critical: 0,
			high: 1,
			medium: 2,
			low: 0,
		});

		const sarifCounts = parseSummaryFromSarif({
			runs: [{ results: [{ level: "error" }, { level: "warning" }] }],
		});
		expect(sarifCounts.total).toBe(2);

		const line = formatOneLineSummary(jsonCounts, 1);
		expect(line).toContain("3 findings");
		expect(line).toContain("exit 1");

		const md = buildStepSummaryMarkdown({
			title: "CipherSins",
			exitCode: 1,
			counts: jsonCounts,
			failOn: "high",
			scannedPaths: "./src",
		});
		expect(md).toContain("## CipherSins");
		expect(md).toContain("| High | 1 |");
	});

	it("CS-ACT-07 upload-sarif step uses sarif-category input", () => {
		const source = readActionYml();
		expect(source).toContain("github/codeql-action/upload-sarif@v3");
		expect(source).toContain("category: ${{ inputs.sarif-category }}");
	});

	it("CS-ACT-08 parseScanOutputFile reads real SARIF shape from CS-CLI-60 fixture", () => {
		const ciDir = path.join(rootDir, "test/fixtures/ci");
		const sarifPath = path.join(ciDir, "out-action-test.sarif");

		if (!fs.existsSync(cliEntry)) {
			return;
		}

		const result = spawnSync(
			process.execPath,
			[
				cliEntry,
				"scan",
				"src",
				"--format",
				"sarif",
				"--output",
				"out-action-test.sarif",
				"--fail-on",
				"high",
			],
			{ encoding: "utf8", cwd: ciDir },
		);

		try {
			expect(result.status).toBe(1);
			const contents = fs.readFileSync(sarifPath, "utf8");
			const counts = parseScanOutputFile("sarif", contents);
			expect(counts.total).toBeGreaterThanOrEqual(1);
		} finally {
			if (fs.existsSync(sarifPath)) {
				fs.unlinkSync(sarifPath);
			}
		}
	});
});

describe("CS-ACT summary edge cases", () => {
	it("CS-ACT-09 empty SARIF results yield zero findings", () => {
		expect(parseSummaryFromSarif({ runs: [{ results: [] }] }).total).toBe(0);
	});

	it("CS-ACT-10 formatOneLineSummary handles zero findings", () => {
		expect(
			formatOneLineSummary(
				{ total: 0, critical: 0, high: 0, medium: 0, low: 0 },
				0,
			),
		).toBe("0 findings, exit 0");
	});

	it("CS-ACT-11 buildStepSummaryMarkdown omits fail-on row when none", () => {
		const md = buildStepSummaryMarkdown({
			title: "Test",
			exitCode: 0,
			counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
			failOn: undefined,
			scannedPaths: ".",
		});
		expect(md).not.toContain("Fail threshold");
	});

	it("CS-ACT-12 run.sh delegates summary to write-summary.mjs", () => {
		const runSource = fs.readFileSync(runSh, "utf8");
		expect(runSource).toContain("write-summary.mjs");
		expect(
			fs.existsSync(
				path.join(rootDir, ".github/actions/scan/write-summary.mjs"),
			),
		).toBe(true);
	});

	it("CS-ACT-13 parseScanOutputFile handles malformed JSON gracefully", () => {
		expect(() => parseScanOutputFile("json", "not-json")).toThrow();
	});

	it("CS-ACT-14 formatOneLineSummary pluralizes single finding", () => {
		expect(
			formatOneLineSummary(
				{ total: 1, critical: 0, high: 1, medium: 0, low: 0 },
				1,
			),
		).toBe("1 finding (1 high), exit 1");
	});

	it("CS-ACT-15 buildStepSummaryMarkdown includes scanned paths", () => {
		const md = buildStepSummaryMarkdown({
			title: "Scan",
			exitCode: 0,
			counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
			scannedPaths: "fixtures/cs-jwt-01/good",
		});
		expect(md).toContain("fixtures/cs-jwt-01/good");
	});

	it("CS-ACT-16 action.yml exposes CLI parity inputs", () => {
		const source = readActionYml();
		for (const input of [
			"include:",
			"exclude:",
			"only:",
			"ignore:",
			"cwd:",
			"no-config:",
			"max-findings:",
			"verbose:",
			"strict-config:",
		]) {
			expect(source).toContain(input);
		}
	});

	it("CS-ACT-17 action outputs include exit-code and findings-count", () => {
		const source = readActionYml();
		expect(source).toContain("exit-code:");
		expect(source).toContain("findings-count:");
		expect(source).toContain("summary:");
	});

	it("CS-ACT-18 parseSummaryFromSarif maps note level to low severity", () => {
		const counts = parseSummaryFromSarif({
			runs: [{ results: [{ level: "note" }, { level: "error" }] }],
		});
		expect(counts.low).toBe(1);
		expect(counts.high).toBe(1);
		expect(counts.total).toBe(2);
	});
});
