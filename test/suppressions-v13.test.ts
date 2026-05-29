import path from "node:path";
import { describe, expect, it } from "vitest";
import { parseSourceFile, parseSuppressions, scan } from "ciphersins";

const fixturesDir = path.resolve(import.meta.dirname, "fixtures/suppressions");

describe("v1.3 inline suppressions", () => {
	it("CS-SUP-V13-01 ignore-next-line suppresses CS-HASH-04", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-hash04.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-V13-02 ignore-next-line suppresses CS-HASH-05", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-hash05.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-V13-03 ignore-next-line suppresses CS-ENC-03", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-enc03.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-V13-04 ignore-next-line suppresses CS-ENC-04", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-enc04.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-V13-05 ignore-next-line suppresses CS-JWT-05", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-jwt05.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-V13-06 ignore-next-line suppresses CS-JWT-06", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-jwt06.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-06")).toBe(false);
		expect(result.findings.some((f) => f.ruleId === "CS-JWT-05")).toBe(true);
	});

	it("CS-SUP-V13-07 ignore-next-line suppresses CS-RNG-02", async () => {
		const file = path.join(fixturesDir, "ignore-next-line-rng02.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-V13-08 same-line ignore suppresses CS-ENC-04", async () => {
		const file = path.join(fixturesDir, "ignore-same-line-enc04.ts");
		const result = await scan({ paths: [file] });
		expect(result.findings).toEqual([]);
	});

	it("CS-SUP-V13-09 parseSuppressions reads CS-HASH-04 next-line directive", () => {
		const file = path.join(fixturesDir, "ignore-next-line-hash04.ts");
		const sourceFile = parseSourceFile(file);
		const parsed = parseSuppressions(sourceFile);
		expect(parsed.suppressions).toEqual([{ line: 5, ruleIds: ["CS-HASH-04"] }]);
	});
});
