import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { ciFixtureDir, rootDir } from "./helpers.js";

const jwt01GoodPath = "fixtures/cs-jwt-01/good";
const ciFixturePath = "test/fixtures/ci";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const runSh = path.join(rootDir, ".github/actions/scan/run.sh");
const cliEntry = path.join(rootDir, "packages/ciphersins/dist/cli.js");

const tempOutputs: string[] = [];

function parseGithubOutput(filePath: string): Record<string, string> {
	const outputs: Record<string, string> = {};
	for (const line of fs.readFileSync(filePath, "utf8").split("\n")) {
		if (!line.trim()) {
			continue;
		}
		const index = line.indexOf("=");
		if (index === -1) {
			continue;
		}
		outputs[line.slice(0, index)] = line.slice(index + 1);
	}
	return outputs;
}

function runActionScan(
	env: Record<string, string>,
	options: { cwd?: string; actionCwd?: string } = {},
) {
	if (!fs.existsSync(cliEntry)) {
		throw new Error("CLI not built — run npm run build first");
	}

	const outputFile = path.join(
		os.tmpdir(),
		`ciphersins-act-out-${Date.now()}-${Math.random().toString(16).slice(2)}.txt`,
	);
	fs.writeFileSync(outputFile, "");
	tempOutputs.push(outputFile);

	const result = spawnSync("bash", [runSh], {
		env: {
			...process.env,
			GITHUB_WORKSPACE: rootDir,
			GITHUB_OUTPUT: outputFile,
			INPUT_VERSION: "workspace",
			INPUT_WRITE_SUMMARY: "false",
			INPUT_NO_COLOR: "true",
			...env,
		},
		cwd: options.actionCwd ?? rootDir,
		encoding: "utf8",
	});

	return {
		status: result.status,
		stdout: result.stdout ?? "",
		stderr: result.stderr ?? "",
		outputs: parseGithubOutput(outputFile),
	};
}

afterEach(() => {
	for (const filePath of tempOutputs.splice(0)) {
		fs.rmSync(filePath, { force: true });
	}
	for (const artifact of fs.readdirSync(rootDir)) {
		if (/^act-.*\.(json|sarif)$/.test(artifact)) {
			fs.rmSync(path.join(rootDir, artifact), { force: true });
		}
	}
});

describe("CS-ACT run.sh integration", () => {
	it("CS-ACT-RUN-01 workspace good fixture exits 0", () => {
		const { status, outputs } = runActionScan({
			INPUT_PATH: jwt01GoodPath,
			INPUT_FAIL_ON: "high",
			INPUT_FORMAT: "json",
			INPUT_OUTPUT: "act-good.json",
		});

		expect(status).toBe(0);
		expect(outputs["exit-code"]).toBe("0");
		expect(Number(outputs["findings-count"])).toBe(0);
	});

	it("CS-ACT-RUN-02 workspace bad CI fixture exits 1", () => {
		const { status, outputs } = runActionScan({
			INPUT_PATH: ciFixturePath,
			INPUT_FAIL_ON: "high",
			INPUT_FORMAT: "json",
			INPUT_OUTPUT: "act-bad.json",
		});

		expect(status).toBe(1);
		expect(outputs["exit-code"]).toBe("1");
		expect(Number(outputs["findings-count"])).toBeGreaterThanOrEqual(1);
	});

	it("CS-ACT-RUN-03 soft-fail returns shell 0 on findings exit 1", () => {
		const { status, outputs } = runActionScan({
			INPUT_PATH: ciFixturePath,
			INPUT_FAIL_ON: "high",
			INPUT_SOFT_FAIL: "true",
			INPUT_FORMAT: "json",
			INPUT_OUTPUT: "act-soft.json",
		});

		expect(status).toBe(0);
		expect(outputs["exit-code"]).toBe("1");
	});

	it("CS-ACT-RUN-04 fail-on none exits 0 despite findings", () => {
		const { status, outputs } = runActionScan({
			INPUT_PATH: ciFixturePath,
			INPUT_FAIL_ON: "none",
			INPUT_FORMAT: "json",
			INPUT_OUTPUT: "act-none.json",
		});

		expect(status).toBe(0);
		expect(outputs["exit-code"]).toBe("0");
		expect(Number(outputs["findings-count"])).toBeGreaterThanOrEqual(1);
	});

	it("CS-ACT-RUN-04b fail-on high still exits 1 on findings", () => {
		const { status, outputs } = runActionScan({
			INPUT_PATH: ciFixturePath,
			INPUT_FAIL_ON: "high",
			INPUT_FORMAT: "json",
			INPUT_OUTPUT: "act-high.json",
		});

		expect(status).toBe(1);
		expect(outputs["exit-code"]).toBe("1");
	});

	it("CS-ACT-RUN-05 comma-separated paths aggregate scan", () => {
		const { status, outputs } = runActionScan({
			INPUT_PATH: `${jwt01GoodPath},${ciFixturePath}`,
			INPUT_FAIL_ON: "none",
			INPUT_FORMAT: "json",
			INPUT_OUTPUT: "act-multi.json",
		});

		expect(status).toBe(0);
		expect(Number(outputs["findings-count"])).toBeGreaterThanOrEqual(1);
	});

	it("CS-ACT-RUN-06 resolves default path to ./src when directory exists", () => {
		const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cs-act-src-"));
		const srcDir = path.join(tempRoot, "src");
		fs.mkdirSync(srcDir);
		fs.writeFileSync(
			path.join(srcDir, "clean.ts"),
			"export const value = 1;\n",
		);

		try {
			const { status, outputs } = runActionScan(
				{
					INPUT_PATH: ".",
					INPUT_FAIL_ON: "none",
					INPUT_FORMAT: "json",
					INPUT_OUTPUT: "act-src-default.json",
					INPUT_CWD: tempRoot,
				},
				{ actionCwd: tempRoot },
			);

			expect(status).toBe(0);
			expect(outputs["exit-code"]).toBe("0");
		} finally {
			fs.rmSync(tempRoot, { recursive: true, force: true });
		}
	});

	it("CS-ACT-RUN-07 missing workspace CLI exits 2", () => {
		const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cs-act-missing-"));
		const outputFile = path.join(tempRoot, "out.txt");
		fs.writeFileSync(outputFile, "");

		const result = spawnSync("bash", [runSh], {
			env: {
				...process.env,
				GITHUB_WORKSPACE: tempRoot,
				GITHUB_OUTPUT: outputFile,
				INPUT_VERSION: "workspace",
				INPUT_PATH: ".",
				INPUT_WRITE_SUMMARY: "false",
			},
			cwd: tempRoot,
			encoding: "utf8",
		});

		try {
			expect(result.status).toBe(2);
			expect(result.stderr).toContain("workspace CLI not found");
		} finally {
			fs.rmSync(tempRoot, { recursive: true, force: true });
		}
	});

	it("CS-ACT-RUN-08 sarif output sets sarif-path output", () => {
		const { outputs } = runActionScan({
			INPUT_PATH: jwt01GoodPath,
			INPUT_FAIL_ON: "none",
			INPUT_FORMAT: "sarif",
			INPUT_OUTPUT: "act-good.sarif",
		});

		expect(outputs["sarif-path"]).toMatch(/act-good\.sarif$/);
		expect(outputs["summary"]).toMatch(/exit 0/);
	});

	it("CS-ACT-RUN-09 include and exclude flags forward to CLI", () => {
		const { status, outputs } = runActionScan({
			INPUT_PATH: jwt01GoodPath,
			INPUT_FAIL_ON: "none",
			INPUT_FORMAT: "json",
			INPUT_OUTPUT: "act-filter.json",
			INPUT_INCLUDE: "**/*.ts",
			INPUT_EXCLUDE: "**/node_modules/**",
		});

		expect(status).toBe(0);
		expect(outputs["exit-code"]).toBe("0");
	});

	it("CS-ACT-RUN-10 only and ignore rule filters forward to CLI", () => {
		const { status, outputs } = runActionScan({
			INPUT_PATH: ciFixturePath,
			INPUT_FAIL_ON: "none",
			INPUT_FORMAT: "json",
			INPUT_OUTPUT: "act-only.json",
			INPUT_ONLY: "CS-JWT-01",
		});

		expect(status).toBe(0);
		expect(Number(outputs["findings-count"])).toBeGreaterThanOrEqual(1);
	});

	it("CS-ACT-RUN-11 no-config skips config discovery", () => {
		const { status, outputs } = runActionScan({
			INPUT_PATH: ciFixturePath,
			INPUT_FAIL_ON: "none",
			INPUT_NO_CONFIG: "true",
			INPUT_FORMAT: "json",
			INPUT_OUTPUT: "act-noconfig.json",
		});

		expect(status).toBe(0);
		expect(outputs["exit-code"]).toBe("0");
		expect(Number(outputs["findings-count"])).toBeGreaterThanOrEqual(1);
	});

	it("CS-ACT-RUN-12 cwd input scopes config and output paths", () => {
		const { status, outputs } = runActionScan({
			INPUT_PATH: "src",
			INPUT_CWD: ciFixtureDir,
			INPUT_FAIL_ON: "none",
			INPUT_NO_CONFIG: "true",
			INPUT_FORMAT: "json",
			INPUT_OUTPUT: "scoped.json",
		});

		expect(status).toBe(0);
		expect(outputs["exit-code"]).toBe("0");
		expect(Number(outputs["findings-count"])).toBeGreaterThanOrEqual(1);
		expect(fs.existsSync(path.join(ciFixtureDir, "scoped.json"))).toBe(true);
		fs.rmSync(path.join(ciFixtureDir, "scoped.json"), { force: true });
	});

	it("CS-ACT-RUN-13 exit code 2 propagates without soft-fail override", () => {
		const { status, outputs } = runActionScan({
			INPUT_PATH: "fixtures/does-not-exist-xyz",
			INPUT_FAIL_ON: "none",
			INPUT_SOFT_FAIL: "true",
			INPUT_FORMAT: "json",
		});

		expect(status).toBeGreaterThanOrEqual(2);
		expect(Number(outputs["exit-code"])).toBeGreaterThanOrEqual(2);
	});

	it("CS-ACT-RUN-14 ignore rule filter reduces findings", () => {
		const allRules = runActionScan({
			INPUT_PATH: ciFixturePath,
			INPUT_FAIL_ON: "none",
			INPUT_FORMAT: "json",
			INPUT_OUTPUT: "act-all.json",
		});
		const ignored = runActionScan({
			INPUT_PATH: ciFixturePath,
			INPUT_FAIL_ON: "none",
			INPUT_IGNORE: "CS-JWT-01",
			INPUT_FORMAT: "json",
			INPUT_OUTPUT: "act-ignore.json",
		});

		expect(Number(allRules.outputs["findings-count"])).toBeGreaterThan(0);
		expect(Number(ignored.outputs["findings-count"])).toBe(0);
	});

	it("CS-ACT-RUN-15 write-summary appends GITHUB_STEP_SUMMARY when enabled", () => {
		const summaryFile = path.join(
			os.tmpdir(),
			`cs-act-summary-${Date.now()}.md`,
		);
		fs.writeFileSync(summaryFile, "");

		const jsonPath = path.join(rootDir, "act-summary-src.json");
		if (!fs.existsSync(cliEntry)) {
			return;
		}

		const scan = spawnSync(
			process.execPath,
			[
				cliEntry,
				"scan",
				ciFixturePath,
				"--format",
				"json",
				"--output",
				jsonPath,
				"--fail-on",
				"none",
			],
			{ encoding: "utf8", cwd: rootDir },
		);
		expect(scan.status).toBe(0);

		const result = spawnSync(
			process.execPath,
			[
				path.join(rootDir, ".github/actions/scan/write-summary.mjs"),
				"json",
				jsonPath,
				"0",
				"Edge summary",
				"none",
				ciFixturePath,
				"true",
			],
			{
				encoding: "utf8",
				env: { ...process.env, GITHUB_STEP_SUMMARY: summaryFile },
			},
		);

		try {
			expect(result.status).toBe(0);
			const summary = fs.readFileSync(summaryFile, "utf8");
			expect(summary).toContain("Edge summary");
			expect(summary).toContain("| Findings |");
		} finally {
			fs.rmSync(summaryFile, { force: true });
			fs.rmSync(jsonPath, { force: true });
		}
	});
});
