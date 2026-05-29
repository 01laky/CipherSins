import ts from "typescript";

function cipherAlgorithmText(expr: ts.Expression): string | undefined {
	if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
		return expr.text;
	}
	return undefined;
}

export function isEcbCipherAlgorithmLiteral(
	expr: ts.Expression | undefined,
): boolean {
	if (expr === undefined) {
		return false;
	}

	const text = cipherAlgorithmText(expr);
	if (text === undefined) {
		return false;
	}

	return /^[\w-]+-ecb$/i.test(text);
}
