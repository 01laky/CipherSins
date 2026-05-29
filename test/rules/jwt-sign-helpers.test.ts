import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
	signCallHasExpiry,
	signCallMissingExpiry,
	signCallUsesNoTimestampWithoutExpiry,
} from "../../packages/ciphersins/src/rules/helpers/jwt-sign-options.js";
import { getSignOptionsArgument } from "../../packages/ciphersins/src/rules/helpers/jwt-verify-options.js";

function parseSource(source: string): ts.SourceFile {
	return ts.createSourceFile(
		"sample.ts",
		source,
		ts.ScriptTarget.Latest,
		true,
		ts.ScriptKind.TS,
	);
}

function findSignCall(sourceFile: ts.SourceFile): ts.CallExpression {
	let found: ts.CallExpression | undefined;

	function visit(node: ts.Node): void {
		if (found) {
			return;
		}
		if (
			ts.isCallExpression(node) &&
			node.expression.getText(sourceFile).includes("sign")
		) {
			found = node;
			return;
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	if (!found) {
		throw new Error("expected jwt.sign call");
	}
	return found;
}

describe("jwt sign option helpers", () => {
	it("CS-JWT-SIGN-01 signCallMissingExpiry on sign without options is true", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"jwt.sign({ sub: 'u' }, 'secret');",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(signCallMissingExpiry(call, sourceFile)).toBe(true);
	});

	it("CS-JWT-SIGN-02 signCallHasExpiry on expiresIn option is true", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"jwt.sign({ sub: 'u' }, 'secret', { expiresIn: '1h' });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(signCallHasExpiry(call, sourceFile)).toBe(true);
		expect(signCallMissingExpiry(call, sourceFile)).toBe(false);
	});

	it("CS-JWT-SIGN-03 signCallHasExpiry on payload exp claim is true", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"jwt.sign({ sub: 'u', exp: 9999999999 }, 'secret');",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(signCallHasExpiry(call, sourceFile)).toBe(true);
	});

	it("CS-JWT-SIGN-04 signCallUsesNoTimestampWithoutExpiry on noTimestamp without expiry", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"jwt.sign({ sub: 'u' }, 'secret', { noTimestamp: true });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(signCallUsesNoTimestampWithoutExpiry(call, sourceFile)).toBe(true);
	});

	it("CS-JWT-SIGN-05 signCallUsesNoTimestampWithoutExpiry clean with expiresIn", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"jwt.sign({ sub: 'u' }, 'secret', { noTimestamp: true, expiresIn: '1h' });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(signCallUsesNoTimestampWithoutExpiry(call, sourceFile)).toBe(false);
	});

	it("CS-JWT-SIGN-06 getSignOptionsArgument returns third argument", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"jwt.sign({ sub: 'u' }, 'secret', { expiresIn: '1h' });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(getSignOptionsArgument(call)?.getText(sourceFile)).toBe(
			"{ expiresIn: '1h' }",
		);
	});

	it("CS-JWT-SIGN-07 signCallMissingExpiry on nbf-only options is true", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"jwt.sign({ sub: 'u' }, 'secret', { notBefore: '1h' });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(signCallMissingExpiry(call, sourceFile)).toBe(true);
	});

	it("CS-JWT-SIGN-08 signCallHasExpiry resolves bound expiresIn variable", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"const expiresIn = '1h';",
			"jwt.sign({ sub: 'u' }, 'secret', { expiresIn });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(signCallHasExpiry(call, sourceFile)).toBe(true);
	});

	it("CS-JWT-SIGN-09 signCallHasExpiry resolves bound exp in payload", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"const exp = 9999999999;",
			"jwt.sign({ sub: 'u', exp }, 'secret');",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(signCallHasExpiry(call, sourceFile)).toBe(true);
	});

	it("CS-JWT-SIGN-10 signCallUsesNoTimestampWithoutExpiry false without noTimestamp", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"jwt.sign({ sub: 'u' }, 'secret', { expiresIn: '1h' });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(signCallUsesNoTimestampWithoutExpiry(call, sourceFile)).toBe(false);
	});

	it("CS-JWT-SIGN-11 signCallUsesNoTimestampWithoutExpiry with exp claim is false", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"jwt.sign({ sub: 'u', exp: 9999999999 }, 'secret', { noTimestamp: true });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(signCallUsesNoTimestampWithoutExpiry(call, sourceFile)).toBe(false);
	});

	it("CS-JWT-SIGN-12 signCallMissingExpiry on empty options object is true", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"jwt.sign({ sub: 'u' }, 'secret', {});",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(signCallMissingExpiry(call, sourceFile)).toBe(true);
	});

	it("CS-JWT-SIGN-13 signCallUsesNoTimestampWithoutExpiry resolves bound noTimestamp shorthand", () => {
		const source = [
			'import jwt from "jsonwebtoken";',
			"const noTimestamp = true;",
			"jwt.sign({ sub: 'u' }, 'secret', { noTimestamp });",
		].join("\n");
		const sourceFile = parseSource(source);
		const call = findSignCall(sourceFile);

		expect(signCallUsesNoTimestampWithoutExpiry(call, sourceFile)).toBe(true);
	});
});
