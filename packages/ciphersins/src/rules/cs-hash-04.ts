import type { Finding, Rule, RuleContext } from "../types.js";
import { collectCallExpressions } from "./helpers/collect-call-expressions.js";
import { createFinding } from "./helpers/finding.js";
import { callHasPasswordContext } from "./helpers/password-context.js";
import {
	getHashBindingsForScrypt,
	isTrackedScryptCall,
	scryptCallHasWeakParams,
	SCRYPT_MIN_BLOCK_SIZE,
	SCRYPT_MIN_COST,
	SCRYPT_MIN_PARALLELIZATION,
} from "./helpers/scrypt-cost.js";

const MESSAGE = `scrypt parameters below minimum (cost ≥ ${SCRYPT_MIN_COST}, blockSize ≥ ${SCRYPT_MIN_BLOCK_SIZE}, parallelization ≥ ${SCRYPT_MIN_PARALLELIZATION}) in password context; increase scrypt cost or use stronger KDF settings.`;
const HELP_URL =
	"https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-HASH-04.md";

export const csHash04Rule: Rule = {
	id: "CS-HASH-04",
	title: "scrypt cost factor too low",
	severity: "medium",
	run(context: RuleContext): Finding[] {
		const bindings = getHashBindingsForScrypt(context.sourceFile);
		const findings: Finding[] = [];

		for (const call of collectCallExpressions(context.sourceFile)) {
			const isScrypt =
				isTrackedScryptCall(call, bindings, "scrypt") ||
				isTrackedScryptCall(call, bindings, "scryptSync");
			if (!isScrypt) {
				continue;
			}

			if (!callHasPasswordContext(call)) {
				continue;
			}

			const method = isTrackedScryptCall(call, bindings, "scryptSync")
				? "scryptSync"
				: "scrypt";
			if (!scryptCallHasWeakParams(call, context.sourceFile, method)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csHash04Rule,
					message: MESSAGE,
					helpUrl: HELP_URL,
					filePath: context.filePath,
					sourceFile: context.sourceFile,
					node: call,
				}),
			);
		}

		return findings;
	},
};
