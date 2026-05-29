import ts from "typescript";

const WEAK_CIPHER_PATTERNS = [
	/^des-/i,
	/^des$/i,
	/^rc4$/i,
	/^rc4-/i,
	/^rc2$/i,
	/^rc2-/i,
	/^bf$/i,
	/^bf-/i,
	/^cast$/i,
	/^cast-/i,
	/^cast5$/i,
	/^cast5-/i,
];

function cipherAlgorithmText(expr: ts.Expression): string | undefined {
	if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
		return expr.text;
	}
	return undefined;
}

export function isWeakCipherAlgorithmLiteral(
	expr: ts.Expression | undefined,
): boolean {
	if (expr === undefined) {
		return false;
	}

	const text = cipherAlgorithmText(expr);
	if (text === undefined) {
		return false;
	}

	if (text.toLowerCase() === "null") {
		return false;
	}

	return WEAK_CIPHER_PATTERNS.some((pattern) => pattern.test(text));
}
