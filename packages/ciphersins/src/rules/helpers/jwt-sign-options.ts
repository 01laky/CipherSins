import ts from "typescript";
import { getSignOptionsArgument } from "./jwt-verify-options.js";

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

function findStringLiteralInitializer(
	sourceFile: ts.SourceFile,
	name: string,
): ts.StringLiteral | ts.NoSubstitutionTemplateLiteral | undefined {
	let found: ts.StringLiteral | ts.NoSubstitutionTemplateLiteral | undefined;

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
				if (
					initializer &&
					(ts.isStringLiteral(initializer) ||
						ts.isNoSubstitutionTemplateLiteral(initializer))
				) {
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

function findBooleanLiteralInitializer(
	sourceFile: ts.SourceFile,
	name: string,
): boolean | undefined {
	let found: boolean | undefined;

	function visit(node: ts.Node): void {
		if (found !== undefined) {
			return;
		}
		if (ts.isVariableStatement(node)) {
			for (const decl of node.declarationList.declarations) {
				if (!ts.isIdentifier(decl.name) || decl.name.text !== name) {
					continue;
				}
				const { initializer } = decl;
				if (initializer?.kind === ts.SyntaxKind.TrueKeyword) {
					found = true;
					return;
				}
				if (initializer?.kind === ts.SyntaxKind.FalseKeyword) {
					found = false;
					return;
				}
			}
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	return found;
}

function isExpiresInPropertyName(name: ts.PropertyName): boolean {
	return (
		(ts.isIdentifier(name) && name.text === "expiresIn") ||
		(ts.isStringLiteral(name) && name.text === "expiresIn")
	);
}

function isNoTimestampPropertyName(name: ts.PropertyName): boolean {
	return (
		(ts.isIdentifier(name) && name.text === "noTimestamp") ||
		(ts.isStringLiteral(name) && name.text === "noTimestamp")
	);
}

function isExpPropertyName(name: ts.PropertyName): boolean {
	return (
		(ts.isIdentifier(name) && name.text === "exp") ||
		(ts.isStringLiteral(name) && name.text === "exp")
	);
}

function expressionHasExpiresIn(
	expr: ts.Expression,
	sourceFile?: ts.SourceFile,
): boolean {
	if (!ts.isObjectLiteralExpression(expr)) {
		return false;
	}

	for (const prop of expr.properties) {
		if (ts.isShorthandPropertyAssignment(prop)) {
			if (!ts.isIdentifier(prop.name) || !isExpiresInPropertyName(prop.name)) {
				continue;
			}
			if (sourceFile) {
				const str = findStringLiteralInitializer(sourceFile, prop.name.text);
				const num = findNumericLiteralInitializer(sourceFile, prop.name.text);
				if (str || num) {
					return true;
				}
			}
			continue;
		}
		if (!ts.isPropertyAssignment(prop)) {
			continue;
		}
		if (!isExpiresInPropertyName(prop.name)) {
			continue;
		}
		const { initializer } = prop;
		if (!initializer) {
			continue;
		}
		if (
			ts.isStringLiteral(initializer) ||
			ts.isNoSubstitutionTemplateLiteral(initializer) ||
			ts.isNumericLiteral(initializer)
		) {
			return true;
		}
		if (sourceFile && ts.isIdentifier(initializer)) {
			const str = findStringLiteralInitializer(sourceFile, initializer.text);
			const num = findNumericLiteralInitializer(sourceFile, initializer.text);
			if (str || num) {
				return true;
			}
		}
	}

	return false;
}

function payloadHasNumericExp(
	payload: ts.Expression | undefined,
	sourceFile?: ts.SourceFile,
): boolean {
	if (!payload || !ts.isObjectLiteralExpression(payload)) {
		return false;
	}

	for (const prop of payload.properties) {
		if (ts.isShorthandPropertyAssignment(prop)) {
			if (!ts.isIdentifier(prop.name) || !isExpPropertyName(prop.name)) {
				continue;
			}
			if (sourceFile) {
				const resolved = findNumericLiteralInitializer(
					sourceFile,
					prop.name.text,
				);
				if (resolved) {
					return true;
				}
			}
			continue;
		}
		if (!ts.isPropertyAssignment(prop)) {
			continue;
		}
		if (!isExpPropertyName(prop.name)) {
			continue;
		}
		const { initializer } = prop;
		if (initializer && ts.isNumericLiteral(initializer)) {
			return true;
		}
		if (sourceFile && initializer && ts.isIdentifier(initializer)) {
			const resolved = findNumericLiteralInitializer(
				sourceFile,
				initializer.text,
			);
			if (resolved) {
				return true;
			}
		}
	}

	return false;
}

function optionsHasNoTimestampTrue(
	expr: ts.Expression,
	sourceFile?: ts.SourceFile,
): boolean {
	if (!ts.isObjectLiteralExpression(expr)) {
		return false;
	}

	for (const prop of expr.properties) {
		if (ts.isShorthandPropertyAssignment(prop)) {
			if (
				!ts.isIdentifier(prop.name) ||
				!isNoTimestampPropertyName(prop.name)
			) {
				continue;
			}
			if (sourceFile) {
				const resolved = findBooleanLiteralInitializer(
					sourceFile,
					prop.name.text,
				);
				if (resolved === true) {
					return true;
				}
			}
			continue;
		}
		if (!ts.isPropertyAssignment(prop)) {
			continue;
		}
		if (!isNoTimestampPropertyName(prop.name)) {
			continue;
		}
		const { initializer } = prop;
		if (initializer?.kind === ts.SyntaxKind.TrueKeyword) {
			return true;
		}
		if (sourceFile && initializer && ts.isIdentifier(initializer)) {
			const resolved = findBooleanLiteralInitializer(
				sourceFile,
				initializer.text,
			);
			if (resolved === true) {
				return true;
			}
		}
	}

	return false;
}

function resolveSignOptionsObjectLiteral(
	expression: ts.Expression,
	sourceFile: ts.SourceFile,
): ts.ObjectLiteralExpression | undefined {
	if (ts.isObjectLiteralExpression(expression)) {
		return expression;
	}
	if (ts.isIdentifier(expression)) {
		const identifierName = expression.text;
		let found: ts.ObjectLiteralExpression | undefined;

		function visit(node: ts.Node): void {
			if (found) {
				return;
			}
			if (ts.isVariableStatement(node)) {
				for (const decl of node.declarationList.declarations) {
					if (
						!ts.isIdentifier(decl.name) ||
						decl.name.text !== identifierName
					) {
						continue;
					}
					const { initializer } = decl;
					if (initializer && ts.isObjectLiteralExpression(initializer)) {
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
	return undefined;
}

export function signCallHasExpiry(
	call: ts.CallExpression,
	sourceFile?: ts.SourceFile,
): boolean {
	const [payload] = call.arguments;
	if (sourceFile && payloadHasNumericExp(payload, sourceFile)) {
		return true;
	}
	if (payloadHasNumericExp(payload)) {
		return true;
	}

	const optionsArg = getSignOptionsArgument(call);
	if (!optionsArg) {
		return false;
	}

	if (sourceFile) {
		const resolved = resolveSignOptionsObjectLiteral(optionsArg, sourceFile);
		if (resolved && expressionHasExpiresIn(resolved, sourceFile)) {
			return true;
		}
	}

	return expressionHasExpiresIn(optionsArg, sourceFile);
}

export function signCallMissingExpiry(
	call: ts.CallExpression,
	sourceFile?: ts.SourceFile,
): boolean {
	return !signCallHasExpiry(call, sourceFile);
}

export function signCallUsesNoTimestampWithoutExpiry(
	call: ts.CallExpression,
	sourceFile?: ts.SourceFile,
): boolean {
	const optionsArg = getSignOptionsArgument(call);
	if (!optionsArg) {
		return false;
	}

	let hasNoTimestamp = optionsHasNoTimestampTrue(optionsArg, sourceFile);
	if (!hasNoTimestamp && sourceFile) {
		const resolved = resolveSignOptionsObjectLiteral(optionsArg, sourceFile);
		if (resolved) {
			hasNoTimestamp = optionsHasNoTimestampTrue(resolved, sourceFile);
		}
	}

	if (!hasNoTimestamp) {
		return false;
	}

	return signCallMissingExpiry(call, sourceFile);
}
