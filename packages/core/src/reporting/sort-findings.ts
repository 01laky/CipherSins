import type { Finding } from "../types.js";

export function sortFindings(findings: Finding[]): Finding[] {
	return [...findings].sort((a, b) => {
		const fileCompare = a.file.localeCompare(b.file);
		if (fileCompare !== 0) {
			return fileCompare;
		}
		if (a.line !== b.line) {
			return a.line - b.line;
		}
		if (a.column !== b.column) {
			return a.column - b.column;
		}
		return a.ruleId.localeCompare(b.ruleId);
	});
}
