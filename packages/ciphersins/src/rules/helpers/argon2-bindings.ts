import ts from "typescript";

const ARGON2_MODULES = new Set(["argon2", "@node-rs/argon2"]);

export interface Argon2Bindings {
	hashIdentifiers: Set<string>;
	hashSyncIdentifiers: Set<string>;
	memberObjects: Set<string>;
}

export function createEmptyArgon2Bindings(): Argon2Bindings {
	return {
		hashIdentifiers: new Set<string>(),
		hashSyncIdentifiers: new Set<string>(),
		memberObjects: new Set<string>(),
	};
}

function isArgon2ModuleSpecifier(specifier: string): boolean {
	return ARGON2_MODULES.has(specifier);
}

function isArgon2RequireCall(node: ts.Node, modules = ARGON2_MODULES): boolean {
	if (!ts.isCallExpression(node)) {
		return false;
	}
	if (!ts.isIdentifier(node.expression) || node.expression.text !== "require") {
		return false;
	}
	const [specifier] = node.arguments;
	return (
		specifier !== undefined &&
		ts.isStringLiteral(specifier) &&
		modules.has(specifier.text)
	);
}

function trackArgon2Identifier(
	importedName: string,
	localName: string,
	bindings: Argon2Bindings,
): void {
	switch (importedName) {
		case "hash":
			bindings.hashIdentifiers.add(localName);
			break;
		case "hashSync":
			bindings.hashSyncIdentifiers.add(localName);
			break;
		default:
			break;
	}
}

function trackArgon2FromRequire(
	name: ts.BindingName,
	initializer: ts.Expression,
	bindings: Argon2Bindings,
): void {
	if (!isArgon2RequireCall(initializer)) {
		return;
	}

	if (ts.isIdentifier(name)) {
		bindings.memberObjects.add(name.text);
		return;
	}

	if (ts.isObjectBindingPattern(name)) {
		for (const element of name.elements) {
			if (element.dotDotDotToken || !ts.isIdentifier(element.name)) {
				continue;
			}
			const localName = element.name.text;
			const importedName = element.propertyName
				? ts.isIdentifier(element.propertyName)
					? element.propertyName.text
					: localName
				: localName;
			trackArgon2Identifier(importedName, localName, bindings);
		}
	}
}

function handleImportDeclaration(
	node: ts.ImportDeclaration,
	bindings: Argon2Bindings,
): void {
	if (!node.moduleSpecifier || !ts.isStringLiteral(node.moduleSpecifier)) {
		return;
	}
	if (!isArgon2ModuleSpecifier(node.moduleSpecifier.text)) {
		return;
	}

	const importClause = node.importClause;
	if (!importClause || importClause.isTypeOnly) {
		return;
	}

	if (importClause.name) {
		bindings.memberObjects.add(importClause.name.text);
	}

	if (
		importClause.namedBindings &&
		ts.isNamespaceImport(importClause.namedBindings)
	) {
		bindings.memberObjects.add(importClause.namedBindings.name.text);
	}

	if (
		importClause.namedBindings &&
		ts.isNamedImports(importClause.namedBindings)
	) {
		for (const element of importClause.namedBindings.elements) {
			if (element.isTypeOnly) {
				continue;
			}
			const localName = element.name.text;
			const importedName = element.propertyName?.text ?? localName;
			trackArgon2Identifier(importedName, localName, bindings);
		}
	}
}

export function getArgon2Bindings(sourceFile: ts.SourceFile): Argon2Bindings {
	const bindings = createEmptyArgon2Bindings();

	function visit(node: ts.Node): void {
		if (ts.isImportDeclaration(node)) {
			handleImportDeclaration(node, bindings);
		}

		if (ts.isVariableStatement(node)) {
			for (const declaration of node.declarationList.declarations) {
				if (declaration.initializer) {
					trackArgon2FromRequire(
						declaration.name,
						declaration.initializer,
						bindings,
					);
				}
			}
		}

		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	return bindings;
}

export function hasArgon2Usage(bindings: Argon2Bindings): boolean {
	return (
		bindings.hashIdentifiers.size > 0 ||
		bindings.hashSyncIdentifiers.size > 0 ||
		bindings.memberObjects.size > 0
	);
}

export function isTrackedArgon2HashCall(
	call: ts.CallExpression,
	bindings: Argon2Bindings,
): boolean {
	const callee = call.expression;

	if (ts.isIdentifier(callee)) {
		if (bindings.hashIdentifiers.has(callee.text)) {
			return true;
		}
		if (bindings.hashSyncIdentifiers.has(callee.text)) {
			return true;
		}
		return false;
	}

	if (ts.isPropertyAccessExpression(callee)) {
		const method = callee.name.text;
		if (method !== "hash" && method !== "hashSync") {
			return false;
		}
		if (
			ts.isIdentifier(callee.expression) &&
			bindings.memberObjects.has(callee.expression.text)
		) {
			return true;
		}
		if (isArgon2RequireCall(callee.expression)) {
			return true;
		}
	}

	return false;
}
