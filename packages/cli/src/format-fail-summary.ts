import { SEVERITIES, type Severity } from "@ciphersins/core";
import { severityRank } from "@ciphersins/core";

export function formatFailSummary(
	summary: Record<Severity, number>,
	failOn: Severity,
): string {
	let total = 0;
	const parts: string[] = [];

	for (const severity of SEVERITIES) {
		if (
			severityRank(severity) >= severityRank(failOn) &&
			summary[severity] > 0
		) {
			total += summary[severity];
			parts.push(`${severity}: ${summary[severity]}`);
		}
	}

	return `error: ${total} finding(s) at or above ${failOn} (${parts.join(", ")})`;
}
