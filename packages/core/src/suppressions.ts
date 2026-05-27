import ts from "typescript";
import type { Finding } from "./types.js";

export interface Suppression {
	line: number;
	ruleIds: string[] | null;
}

const SUPPRESSION_PATTERN =
	/ciphersins-ignore(?:-next-line)?(?:\s+([A-Z0-9-,]+))?/i;

function collectCommentRanges(
	sourceFile: ts.SourceFile,
): Array<{ pos: number; end: number }> {
	const ranges: Array<{ pos: number; end: number }> = [];
	const fullText = sourceFile.getFullText();

	const visit = (node: ts.Node): void => {
		ts.forEachLeadingCommentRange(fullText, node.getFullStart(), (pos, end) => {
			ranges.push({ pos, end });
		});
		ts.forEachTrailingCommentRange(fullText, node.getEnd(), (pos, end) => {
			ranges.push({ pos, end });
		});
		ts.forEachChild(node, visit);
	};

	visit(sourceFile);
	return ranges;
}

function parseRuleIdList(raw: string | undefined): string[] | null {
	if (!raw) {
		return null;
	}
	const ruleIds = raw
		.split(",")
		.map((part) => part.trim())
		.filter(Boolean);
	return ruleIds.length > 0 ? ruleIds : null;
}

export function parseSuppressions(sourceFile: ts.SourceFile): Suppression[] {
	const suppressions: Suppression[] = [];
	const fullText = sourceFile.getFullText();

	for (const range of collectCommentRanges(sourceFile)) {
		const text = fullText.slice(range.pos, range.end);
		const match = text.match(SUPPRESSION_PATTERN);
		if (!match) {
			continue;
		}

		const isNextLine = /ignore-next-line/i.test(text);
		const commentLine =
			sourceFile.getLineAndCharacterOfPosition(range.pos).line + 1;
		const targetLine = isNextLine ? commentLine + 1 : commentLine;

		suppressions.push({
			line: targetLine,
			ruleIds: parseRuleIdList(match[1]),
		});
	}

	const seen = new Set<string>();
	return suppressions.filter((suppression) => {
		const key = `${suppression.line}:${suppression.ruleIds?.join(",") ?? "*"}`;
		if (seen.has(key)) {
			return false;
		}
		seen.add(key);
		return true;
	});
}

export function applySuppressions(
	findings: Finding[],
	suppressionsByFile: Map<string, Suppression[]>,
	allowCriticalIgnore: boolean,
): Finding[] {
	return findings.filter((finding) => {
		const suppressions = suppressionsByFile.get(finding.file) ?? [];

		for (const suppression of suppressions) {
			if (suppression.line !== finding.line) {
				continue;
			}
			if (
				suppression.ruleIds !== null &&
				!suppression.ruleIds.includes(finding.ruleId)
			) {
				continue;
			}
			if (finding.severity === "critical" && !allowCriticalIgnore) {
				return true;
			}
			return false;
		}

		return true;
	});
}
