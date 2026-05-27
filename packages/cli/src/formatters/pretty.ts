import { formatRelativePath, type ScanResult } from "@ciphersins/core";

export function formatPretty(result: ScanResult, cwd: string): string {
	if (result.findings.length === 0) {
		return "No findings.\n";
	}

	const lines: string[] = [];
	for (const finding of result.findings) {
		const displayPath = formatRelativePath(finding.file, cwd);
		lines.push(
			`${displayPath}:${finding.line}:${finding.column}  ${finding.ruleId}  ${finding.severity}`,
		);
		lines.push(`  ${finding.message}`);
		if (finding.helpUrl) {
			lines.push(`  ${finding.helpUrl}`);
		}
	}
	return `${lines.join("\n")}\n`;
}
