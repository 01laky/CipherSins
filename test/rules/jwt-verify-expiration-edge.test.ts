import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseSourceFile, scan } from "ciphersins";
import { collectCallExpressions } from "../../packages/ciphersins/src/rules/helpers/collect-call-expressions.js";
import {
	getJsonWebTokenBindings,
	matchesJsonWebTokenMethodCall,
} from "../../packages/ciphersins/src/rules/helpers/jsonwebtoken-bindings.js";
import { verifyCallIgnoresExpiration } from "../../packages/ciphersins/src/rules/helpers/jwt-verify-options.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "../..");

function verifyCallFrom(source: string) {
	const sourceFile = parseSourceFile("snippet.ts", source);
	const bindings = getJsonWebTokenBindings(sourceFile);
	const call = collectCallExpressions(sourceFile).find((entry) =>
		matchesJsonWebTokenMethodCall(entry, bindings, "verify"),
	);
	if (!call) {
		throw new Error("expected verify call");
	}
	return { call, sourceFile };
}

function fixturePath(segment: "bad" | "good", name: string): string {
	return path.join(rootDir, "fixtures/cs-jwt-04", segment, name);
}

function filterJwt04(findings: { ruleId: string }[]) {
	return findings.filter((finding) => finding.ruleId === "CS-JWT-04");
}

describe("CS-JWT-04 v1.1 expiration edge cases", () => {
	it("CS-JWT-EXP-05d inline nested spread literal ignoreExpiration is detected", () => {
		const source =
			"import jwt from 'jsonwebtoken';\njwt.verify(token, secret, { ...{ ignoreExpiration: true }, algorithms: ['HS256'] });\n";
		const { call, sourceFile } = verifyCallFrom(source);
		expect(verifyCallIgnoresExpiration(call, sourceFile)).toBe(true);
	});

	it("CS-JWT-EXP-05e chained variable spread ignoreExpiration is detected", () => {
		const source =
			"import jwt from 'jsonwebtoken';\nconst inner = { ignoreExpiration: true };\nconst outer = { ...inner };\njwt.verify(token, secret, { ...outer, algorithms: ['HS256'] });\n";
		const { call, sourceFile } = verifyCallFrom(source);
		expect(verifyCallIgnoresExpiration(call, sourceFile)).toBe(true);
	});

	it("CS-JWT-EXP-05f variable opts with ignoreExpiration false is not detected", () => {
		const source =
			"import jwt from 'jsonwebtoken';\nconst opts = { ignoreExpiration: false };\njwt.verify(token, secret, opts);\n";
		const { call, sourceFile } = verifyCallFrom(source);
		expect(verifyCallIgnoresExpiration(call, sourceFile)).toBe(false);
	});

	it("CS-JWT-EXP-05g let-bound opts literal ignoreExpiration is detected", () => {
		const source =
			"import jwt from 'jsonwebtoken';\nlet opts = { ignoreExpiration: true };\njwt.verify(token, secret, opts);\n";
		const { call, sourceFile } = verifyCallFrom(source);
		expect(verifyCallIgnoresExpiration(call, sourceFile)).toBe(true);
	});

	it("CS-JWT-EXP-05h unrelated variable name does not resolve ignoreExpiration", () => {
		const source =
			"import jwt from 'jsonwebtoken';\nconst options = { maxAge: '1h' };\njwt.verify(token, secret, options);\n";
		const { call, sourceFile } = verifyCallFrom(source);
		expect(verifyCallIgnoresExpiration(call, sourceFile)).toBe(false);
	});

	it("CS-JWT-EXP-05i indirect boolean ref in variable opts stays clean", () => {
		const source =
			"import jwt from 'jsonwebtoken';\nconst skip = true;\nconst opts = { ignoreExpiration: skip };\njwt.verify(token, secret, opts);\n";
		const { call, sourceFile } = verifyCallFrom(source);
		expect(verifyCallIgnoresExpiration(call, sourceFile)).toBe(false);
	});

	it("CS-JWT-EXP-05j inline plus spread both containing ignoreExpiration is detected", () => {
		const source =
			"import jwt from 'jsonwebtoken';\nconst base = { ignoreExpiration: true };\njwt.verify(token, secret, { ...base, ignoreExpiration: true });\n";
		const { call, sourceFile } = verifyCallFrom(source);
		expect(verifyCallIgnoresExpiration(call, sourceFile)).toBe(true);
	});

	it("CS-JWT-EXP-05k multiple verify calls only flags variable-bound ignoreExpiration", () => {
		const source = `import jwt from "jsonwebtoken";
const bad = { ignoreExpiration: true };
const good = { algorithms: ["HS256"] };
jwt.verify(token, secret, good);
jwt.verify(token, secret, bad);
`;
		const sourceFile = parseSourceFile("multi.ts", source);
		const bindings = getJsonWebTokenBindings(sourceFile);
		const verifyCalls = collectCallExpressions(sourceFile).filter((call) =>
			matchesJsonWebTokenMethodCall(call, bindings, "verify"),
		);
		expect(verifyCalls).toHaveLength(2);
		expect(verifyCallIgnoresExpiration(verifyCalls[0]!, sourceFile)).toBe(
			false,
		);
		expect(verifyCallIgnoresExpiration(verifyCalls[1]!, sourceFile)).toBe(true);
	});

	it("CS-JWT-04-112 scan flags verify-options-variable-exp-literal fixture", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-options-variable-exp-literal.ts")],
			cwd: rootDir,
		});
		expect(filterJwt04(result.findings)).toHaveLength(1);
	});

	it("CS-JWT-04-113 scan flags verify-spread-from-variable-exp fixture", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-spread-from-variable-exp.ts")],
			cwd: rootDir,
		});
		expect(filterJwt04(result.findings)).toHaveLength(1);
	});

	it("CS-JWT-04-114 scan keeps verify-options-variable-exp indirect ref clean", async () => {
		const result = await scan({
			paths: [fixturePath("good", "verify-options-variable-exp.ts")],
			cwd: rootDir,
		});
		expect(filterJwt04(result.findings)).toEqual([]);
	});

	it("CS-JWT-04-115 scan keeps verify-spread-ignore-expiration inline literal flagged once", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-spread-ignore-expiration.ts")],
			cwd: rootDir,
		});
		expect(filterJwt04(result.findings)).toHaveLength(1);
	});

	it("CS-JWT-04-116 inline ignoreExpiration still flagged without variable resolution", async () => {
		const result = await scan({
			paths: [fixturePath("bad", "verify-ignore-expiration-only.ts")],
			cwd: rootDir,
		});
		expect(filterJwt04(result.findings)).toHaveLength(1);
	});
});
