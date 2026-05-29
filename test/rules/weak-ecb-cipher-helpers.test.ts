import ts from "typescript";
import { describe, expect, it } from "vitest";
import { isEcbCipherAlgorithmLiteral } from "../../packages/ciphersins/src/rules/helpers/ecb-cipher-algorithms.js";
import { isWeakCipherAlgorithmLiteral } from "../../packages/ciphersins/src/rules/helpers/weak-cipher-algorithms.js";

function stringExpr(text: string): ts.StringLiteral {
	const sourceFile = ts.createSourceFile(
		"literal.ts",
		`const _ = "${text}";\n`,
		ts.ScriptTarget.Latest,
		true,
		ts.ScriptKind.TS,
	);
	const stmt = sourceFile.statements[0];
	if (!stmt || !ts.isVariableStatement(stmt)) {
		throw new Error("expected variable statement");
	}
	const decl = stmt.declarationList.declarations[0];
	if (!decl?.initializer || !ts.isStringLiteral(decl.initializer)) {
		throw new Error("expected string literal");
	}
	return decl.initializer;
}

describe("weak and ecb cipher algorithm helpers", () => {
	it("CS-WEAK-01 des-cbc is weak cipher algorithm", () => {
		expect(isWeakCipherAlgorithmLiteral(stringExpr("des-cbc"))).toBe(true);
	});

	it("CS-WEAK-02 rc4 is weak cipher algorithm", () => {
		expect(isWeakCipherAlgorithmLiteral(stringExpr("rc4"))).toBe(true);
	});

	it("CS-WEAK-03 bf is weak cipher algorithm", () => {
		expect(isWeakCipherAlgorithmLiteral(stringExpr("bf"))).toBe(true);
	});

	it("CS-WEAK-04 cast5 is weak cipher algorithm", () => {
		expect(isWeakCipherAlgorithmLiteral(stringExpr("cast5"))).toBe(true);
	});

	it("CS-WEAK-05 aes-256-gcm is not weak cipher algorithm", () => {
		expect(isWeakCipherAlgorithmLiteral(stringExpr("aes-256-gcm"))).toBe(false);
	});

	it("CS-WEAK-06 chacha20-poly1305 is not weak cipher algorithm", () => {
		expect(isWeakCipherAlgorithmLiteral(stringExpr("chacha20-poly1305"))).toBe(
			false,
		);
	});

	it("CS-WEAK-07 null algorithm literal is not weak", () => {
		expect(isWeakCipherAlgorithmLiteral(stringExpr("null"))).toBe(false);
	});

	it("CS-ECB-01 aes-128-ecb is ecb cipher algorithm", () => {
		expect(isEcbCipherAlgorithmLiteral(stringExpr("aes-128-ecb"))).toBe(true);
	});

	it("CS-ECB-02 AES-256-ECB uppercase is ecb cipher algorithm", () => {
		expect(isEcbCipherAlgorithmLiteral(stringExpr("AES-256-ECB"))).toBe(true);
	});

	it("CS-ECB-03 aes-256-cbc is not ecb cipher algorithm", () => {
		expect(isEcbCipherAlgorithmLiteral(stringExpr("aes-256-cbc"))).toBe(false);
	});

	it("CS-ECB-04 undefined expression is not ecb cipher algorithm", () => {
		expect(isEcbCipherAlgorithmLiteral(undefined)).toBe(false);
	});

	it("CS-WEAK-08 undefined expression is not weak cipher algorithm", () => {
		expect(isWeakCipherAlgorithmLiteral(undefined)).toBe(false);
	});
});
