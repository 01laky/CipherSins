import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { ciFixtureDir, cliEntry } from "./helpers.js";

describe("CS-CLI CI workflow fixture", () => {
	it("CS-CLI-60 ci fixture scan sarif output fail-on high exits 1 with CS-JWT-01", () => {
		const outputPath = path.join(ciFixtureDir, "out.sarif");
		if (fs.existsSync(outputPath)) {
			fs.unlinkSync(outputPath);
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
				"out.sarif",
				"--fail-on",
				"high",
			],
			{
				encoding: "utf8",
				cwd: ciFixtureDir,
			},
		);

		try {
			expect(result.status).toBe(1);
			expect(fs.existsSync(outputPath)).toBe(true);
			const doc = JSON.parse(fs.readFileSync(outputPath, "utf8"));
			const jwt01Hits = doc.runs[0].results.filter(
				(entry: { ruleId: string }) => entry.ruleId === "CS-JWT-01",
			);
			expect(jwt01Hits.length).toBeGreaterThanOrEqual(1);
		} finally {
			if (fs.existsSync(outputPath)) {
				fs.unlinkSync(outputPath);
			}
		}
	});
});
