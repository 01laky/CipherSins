import ts from "typescript";
import { getEnclosingFunctionLike } from "./enclosing-function.js";

type EnclosingFunctionLike =
	| ts.FunctionDeclaration
	| ts.MethodDeclaration
	| ts.FunctionExpression
	| ts.ArrowFunction
	| ts.ConstructorDeclaration
	| ts.GetAccessorDeclaration
	| ts.SetAccessorDeclaration;

function isEnclosingFunctionLike(node: ts.Node): node is EnclosingFunctionLike {
	return (
		ts.isFunctionDeclaration(node) ||
		ts.isMethodDeclaration(node) ||
		ts.isFunctionExpression(node) ||
		ts.isArrowFunction(node) ||
		ts.isConstructorDeclaration(node) ||
		ts.isGetAccessorDeclaration(node) ||
		ts.isSetAccessorDeclaration(node)
	);
}

function isNodeWithinScope(node: ts.Node, scope: ts.Node): boolean {
	let current: ts.Node | undefined = node;
	while (current) {
		if (current === scope) {
			return true;
		}
		current = current.parent;
	}
	return false;
}

function collectDirectIdentifierCallsInScope(
	scope: EnclosingFunctionLike,
): ts.Identifier[] {
	if (!scope.body) {
		return [];
	}

	const calls: ts.Identifier[] = [];

	function visit(node: ts.Node): void {
		if (node !== scope && isEnclosingFunctionLike(node)) {
			return;
		}
		if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
			calls.push(node.expression);
		}
		ts.forEachChild(node, visit);
	}

	visit(scope.body);
	return calls;
}

function findFunctionBodyForName(
	sourceFile: ts.SourceFile,
	name: string,
): ts.Node | undefined {
	let found: ts.Node | undefined;

	function visit(node: ts.Node): void {
		if (found) {
			return;
		}
		if (
			ts.isFunctionDeclaration(node) &&
			node.name?.text === name &&
			node.body
		) {
			found = node.body;
			return;
		}
		if (ts.isVariableStatement(node)) {
			for (const decl of node.declarationList.declarations) {
				if (!ts.isIdentifier(decl.name) || decl.name.text !== name) {
					continue;
				}
				const { initializer } = decl;
				if (
					initializer &&
					(ts.isArrowFunction(initializer) ||
						ts.isFunctionExpression(initializer)) &&
					initializer.body
				) {
					found = initializer.body;
					return;
				}
			}
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	return found;
}

/**
 * Returns true when `verifyCall` can suppress a `decodeCall`:
 * - verify in the same function as decode (including nested inner functions), or
 * - verify in a function the decode-bearing function calls directly by name (same file).
 */
export function verifyCallSuppressesDecode(
	decodeCall: ts.CallExpression,
	verifyCall: ts.CallExpression,
	sourceFile: ts.SourceFile,
): boolean {
	const decodeScope = getEnclosingFunctionLike(decodeCall);
	if (decodeScope) {
		if (isNodeWithinScope(verifyCall, decodeScope)) {
			return true;
		}

		for (const callee of collectDirectIdentifierCallsInScope(decodeScope)) {
			const calleeBody = findFunctionBodyForName(sourceFile, callee.text);
			if (calleeBody && isNodeWithinScope(verifyCall, calleeBody)) {
				return true;
			}
		}

		return false;
	}

	return getEnclosingFunctionLike(verifyCall) === undefined;
}
