import ts from "typescript";
import { describe, expect, it } from "vitest";
import { RNG_MIN_AUTH_BYTES } from "ciphersins";
import { getCipherBindings } from "../../packages/ciphersins/src/rules/helpers/crypto-cipher-bindings.js";
import { randomBytesCallHasInsufficientLength } from "../../packages/ciphersins/src/rules/helpers/random-bytes-length.js";

function parseSource(source: string): ts.SourceFile {
	return ts.createSourceFile(
		"sample.ts",
		source,
		ts.ScriptTarget.Latest,
		true,
		ts.ScriptKind.TS,
	);
}

function findRandomBytesCall(sourceFile: ts.SourceFile): ts.CallExpression {
	let found: ts.CallExpression | undefined;

	function visit(node: ts.Node): void {
		if (found) {
			return;
		}
		if (
			ts.isCallExpression(node) &&
			node.expression.getText(sourceFile).includes("randomBytes")
		) {
			found = node;
			return;
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	if (!found) {
		throw new Error("expected randomBytes call");
	}
	return found;
}

describe("randomBytes length helpers", () => {
	it("CS-RNG-LEN-01 RNG_MIN_AUTH_BYTES is 16", () => {
		expect(RNG_MIN_AUTH_BYTES).toBe(16);
	});

	it("CS-RNG-LEN-02 randomBytes(8) has insufficient length", () => {
		const source = [
			'import { randomBytes } from "crypto";',
			"randomBytes(8);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const call = findRandomBytesCall(sourceFile);

		expect(
			randomBytesCallHasInsufficientLength(call, bindings, sourceFile),
		).toBe(true);
	});

	it("CS-RNG-LEN-03 randomBytes(16) has sufficient length", () => {
		const source = [
			'import { randomBytes } from "crypto";',
			"randomBytes(16);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const call = findRandomBytesCall(sourceFile);

		expect(
			randomBytesCallHasInsufficientLength(call, bindings, sourceFile),
		).toBe(false);
	});

	it("CS-RNG-LEN-04 randomBytes(15) has insufficient length", () => {
		const source = [
			'import { randomBytes } from "crypto";',
			"randomBytes(15);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const call = findRandomBytesCall(sourceFile);

		expect(
			randomBytesCallHasInsufficientLength(call, bindings, sourceFile),
		).toBe(true);
	});

	it("CS-RNG-LEN-05 crypto.randomBytes member access tracked", () => {
		const source = [
			'import crypto from "crypto";',
			"crypto.randomBytes(4);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const call = findRandomBytesCall(sourceFile);

		expect(
			randomBytesCallHasInsufficientLength(call, bindings, sourceFile),
		).toBe(true);
	});

	it("CS-RNG-LEN-06 resolves same-file const length variable", () => {
		const source = [
			'import { randomBytes } from "crypto";',
			"const n = 12;",
			"randomBytes(n);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const call = findRandomBytesCall(sourceFile);

		expect(
			randomBytesCallHasInsufficientLength(call, bindings, sourceFile),
		).toBe(true);
	});

	it("CS-RNG-LEN-07 non-tracked randomBytes call returns false", () => {
		const source =
			"function randomBytes(n: number) { return n; }\nrandomBytes(4);";
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const call = findRandomBytesCall(sourceFile);

		expect(
			randomBytesCallHasInsufficientLength(call, bindings, sourceFile),
		).toBe(false);
	});

	it("CS-RNG-LEN-08 variable length without same-file literal returns false", () => {
		const source = [
			'import { randomBytes } from "crypto";',
			"randomBytes(size);",
		].join("\n");
		const sourceFile = parseSource(source);
		const bindings = getCipherBindings(sourceFile);
		const call = findRandomBytesCall(sourceFile);

		expect(
			randomBytesCallHasInsufficientLength(call, bindings, sourceFile),
		).toBe(false);
	});
});
