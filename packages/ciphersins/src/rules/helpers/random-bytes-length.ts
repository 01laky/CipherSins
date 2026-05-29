import ts from "typescript";
import type { CipherBindings } from "./crypto-cipher-bindings.js";
import { matchesCipherMethodCall } from "./crypto-cipher-bindings.js";

export const RNG_MIN_AUTH_BYTES = 16;

function findNumericLiteralInitializer(
	sourceFile: ts.SourceFile,
	name: string,
): ts.NumericLiteral | undefined {
	let found: ts.NumericLiteral | undefined;

	function visit(node: ts.Node): void {
		if (found) {
			return;
		}
		if (ts.isVariableStatement(node)) {
			for (const decl of node.declarationList.declarations) {
				if (!ts.isIdentifier(decl.name) || decl.name.text !== name) {
					continue;
				}
				const { initializer } = decl;
				if (initializer && ts.isNumericLiteral(initializer)) {
					found = initializer;
					return;
				}
			}
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	return found;
}

function resolveLengthValue(
	expr: ts.Expression | undefined,
	sourceFile: ts.SourceFile,
): number | undefined {
	if (expr === undefined) {
		return undefined;
	}
	if (ts.isNumericLiteral(expr)) {
		return Number(expr.text);
	}
	if (ts.isIdentifier(expr)) {
		const resolved = findNumericLiteralInitializer(sourceFile, expr.text);
		if (resolved) {
			return Number(resolved.text);
		}
	}
	return undefined;
}

export function randomBytesCallHasInsufficientLength(
	call: ts.CallExpression,
	bindings: CipherBindings,
	sourceFile: ts.SourceFile,
): boolean {
	if (!matchesCipherMethodCall(call, bindings, "randomBytes")) {
		return false;
	}

	const [lengthArg] = call.arguments;
	const length = resolveLengthValue(lengthArg, sourceFile);
	if (length === undefined) {
		return false;
	}

	return length < RNG_MIN_AUTH_BYTES;
}
