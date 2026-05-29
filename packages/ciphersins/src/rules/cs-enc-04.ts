import type { Finding, Rule, RuleContext } from "../types.js";
import { collectCallExpressions } from "./helpers/collect-call-expressions.js";
import {
	getCipherAlgorithmArgument,
	getCipherBindings,
	matchesCipherMethodCall,
} from "./helpers/crypto-cipher-bindings.js";
import { isEcbCipherAlgorithmLiteral } from "./helpers/ecb-cipher-algorithms.js";
import { createFinding } from "./helpers/finding.js";

const MESSAGE =
	"ECB mode cipher (algorithm ending with -ecb); use a mode with proper IV handling such as GCM or CBC.";
const HELP_URL =
	"https://github.com/01laky/CipherSins/blob/main/docs/rules/CS-ENC-04.md";

export const csEnc04Rule: Rule = {
	id: "CS-ENC-04",
	title: "ECB mode cipher",
	severity: "high",
	run(context: RuleContext): Finding[] {
		const bindings = getCipherBindings(context.sourceFile);
		const findings: Finding[] = [];

		for (const call of collectCallExpressions(context.sourceFile)) {
			const isCipheriv = matchesCipherMethodCall(
				call,
				bindings,
				"createCipheriv",
			);
			const isDecipheriv = matchesCipherMethodCall(
				call,
				bindings,
				"createDecipheriv",
			);
			if (!isCipheriv && !isDecipheriv) {
				continue;
			}

			const algorithm = getCipherAlgorithmArgument(call);
			if (!isEcbCipherAlgorithmLiteral(algorithm)) {
				continue;
			}

			findings.push(
				createFinding({
					rule: csEnc04Rule,
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
