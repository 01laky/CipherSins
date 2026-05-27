import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "@ciphersins/core";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");

const jwtGoodDir = path.join(rootDir, "fixtures/cs-jwt-01/good");
const cmpGoodDir = path.join(rootDir, "fixtures/cs-cmp-01/good");
const rngGoodDir = path.join(rootDir, "fixtures/cs-rng-01/good");
const hashGoodDir = path.join(rootDir, "fixtures/cs-hash-01/good");

const jwtBadDir = path.join(rootDir, "fixtures/cs-jwt-01/bad");
const cmpBadDir = path.join(rootDir, "fixtures/cs-cmp-01/bad");
const rngBadDir = path.join(rootDir, "fixtures/cs-rng-01/bad");
const hashBadDir = path.join(rootDir, "fixtures/cs-hash-01/bad");

const edgeCasesDir = path.join(rootDir, "test/fixtures/edge-cases");

describe("cross-rule integration", () => {
	it("CS-INT-01 all good fixture directories scan clean with zero total findings", async () => {
		const result = await scan({
			paths: [jwtGoodDir, cmpGoodDir, rngGoodDir, hashGoodDir],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-02 all bad fixture directories include JWT, CMP, RNG, and HASH rule hits", async () => {
		const result = await scan({
			paths: [jwtBadDir, cmpBadDir, rngBadDir, hashBadDir],
			cwd: rootDir,
		});

		const ruleIds = new Set(result.findings.map((f) => f.ruleId));
		expect(ruleIds.has("CS-JWT-01")).toBe(true);
		expect(ruleIds.has("CS-CMP-01")).toBe(true);
		expect(ruleIds.has("CS-RNG-01")).toBe(true);
		expect(ruleIds.has("CS-HASH-01")).toBe(true);
	});

	it("CS-INT-03 jwt good fixtures stay clean with CMP and RNG rules active", async () => {
		const result = await scan({ paths: [jwtGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-04 combined bad directories yield exact per-rule finding counts", async () => {
		const result = await scan({
			paths: [jwtBadDir, cmpBadDir, rngBadDir],
			cwd: rootDir,
		});

		const byRule = (ruleId: string) =>
			result.findings.filter((f) => f.ruleId === ruleId).length;

		expect(byRule("CS-JWT-01")).toBe(16);
		expect(byRule("CS-CMP-01")).toBe(13);
		expect(byRule("CS-RNG-01")).toBe(12);
		expect(result.findings).toHaveLength(41);
	});

	it("CS-INT-05 cmp and rng good directories stay clean when scanned together", async () => {
		const result = await scan({
			paths: [cmpGoodDir, rngGoodDir],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-06 cmp and hash good directories stay clean when scanned together", async () => {
		const result = await scan({
			paths: [cmpGoodDir, hashGoodDir],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-07 combined bad directories include CS-HASH-01", async () => {
		const result = await scan({
			paths: [jwtBadDir, cmpBadDir, rngBadDir, hashBadDir],
			cwd: rootDir,
		});

		const ruleIds = new Set(result.findings.map((f) => f.ruleId));
		expect(ruleIds.has("CS-JWT-01")).toBe(true);
		expect(ruleIds.has("CS-CMP-01")).toBe(true);
		expect(ruleIds.has("CS-RNG-01")).toBe(true);
		expect(ruleIds.has("CS-HASH-01")).toBe(true);
	});

	it("CS-INT-08 combined bad directories yield exact per-rule finding counts with HASH", async () => {
		const result = await scan({
			paths: [jwtBadDir, cmpBadDir, rngBadDir, hashBadDir],
			cwd: rootDir,
		});

		const byRule = (ruleId: string) =>
			result.findings.filter((f) => f.ruleId === ruleId).length;

		expect(byRule("CS-JWT-01")).toBe(16);
		expect(byRule("CS-CMP-01")).toBe(13);
		expect(byRule("CS-RNG-01")).toBe(12);
		expect(byRule("CS-HASH-01")).toBe(27);
		expect(result.findings).toHaveLength(68);
	});

	it("CS-INT-09 jwt good fixtures stay clean with four rules active", async () => {
		const result = await scan({ paths: [jwtGoodDir], cwd: rootDir });

		expect(result.findings).toEqual([]);
	});

	it("CS-INT-10 hash good and jwt bad in one scan yields only JWT findings", async () => {
		const result = await scan({
			paths: [hashGoodDir, jwtBadDir],
			cwd: rootDir,
		});

		expect(result.findings.length).toBeGreaterThan(0);
		expect(result.findings.every((f) => f.ruleId === "CS-JWT-01")).toBe(true);
	});

	it("CS-INT-11 all four good dirs plus edge-cases scan clean", async () => {
		const result = await scan({
			paths: [jwtGoodDir, cmpGoodDir, rngGoodDir, hashGoodDir, edgeCasesDir],
			cwd: rootDir,
		});

		expect(result.findings).toEqual([]);
	});
});
