import ts from "typescript";
import type { Finding, Rule, RuleContext } from "../types.js";
import { collectCallExpressions } from "./helpers/collect-call-expressions.js";
import { createFinding } from "./helpers/finding.js";
import {
	getJsonWebTokenBindings,
	hasJsonWebTokenUsage,
	isJsonWebTokenRequireCall,
	matchesJsonWebTokenMethodCall,
} from "./helpers/jsonwebtoken-bindings.js";
import { signCallMissingExpiry } from "./helpers/jwt-sign-options.js";

const MESSAGE =
	"jwt.sign() without expiresIn or exp claim; tokens may never expire.";
const HELP_URL =
	"https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-JWT-05.md";

export const csJwt05Rule: Rule = {
	id: "CS-JWT-05",
	title: "JWT sign without expiry",
	severity: "medium",
	run(context: RuleContext): Finding[] {
		const bindings = getJsonWebTokenBindings(context.sourceFile);
		const calls = collectCallExpressions(context.sourceFile);

		for (const call of calls) {
			if (isJsonWebTokenRequireCall(call.expression)) {
				bindings.hasInlineRequire = true;
			}
			if (
				ts.isPropertyAccessExpression(call.expression) &&
				isJsonWebTokenRequireCall(call.expression.expression)
			) {
				bindings.hasInlineRequire = true;
			}
		}

		if (!hasJsonWebTokenUsage(bindings)) {
			return [];
		}

		const findings: Finding[] = [];

		for (const call of calls) {
			if (!matchesJsonWebTokenMethodCall(call, bindings, "sign")) {
				continue;
			}

			if (!signCallMissingExpiry(call, context.sourceFile)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csJwt05Rule,
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
