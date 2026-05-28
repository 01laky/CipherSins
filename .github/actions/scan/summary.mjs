#!/usr/bin/env node
/**
 * Build GitHub Step Summary markdown and one-line summary from scan output.
 * Used by .github/actions/scan/run.sh and vitest (CS-ACT-06).
 */

export function parseSummaryFromJson(doc) {
	const summary = doc.summary ?? {};
	const total =
		(summary.critical ?? 0) +
		(summary.high ?? 0) +
		(summary.medium ?? 0) +
		(summary.low ?? 0);

	return {
		total,
		critical: summary.critical ?? 0,
		high: summary.high ?? 0,
		medium: summary.medium ?? 0,
		low: summary.low ?? 0,
	};
}

export function parseSummaryFromSarif(doc) {
	const results = doc.runs?.[0]?.results ?? [];
	const counts = { critical: 0, high: 0, medium: 0, low: 0 };

	for (const result of results) {
		const level = result.level ?? "warning";
		if (level === "error") {
			counts.high += 1;
		} else if (level === "warning") {
			counts.medium += 1;
		} else if (level === "note") {
			counts.low += 1;
		} else {
			counts.medium += 1;
		}
	}

	const total = counts.critical + counts.high + counts.medium + counts.low;
	return { total, ...counts };
}

export function formatOneLineSummary(counts, exitCode) {
	const parts = [];
	if (counts.critical > 0) {
		parts.push(`${counts.critical} critical`);
	}
	if (counts.high > 0) {
		parts.push(`${counts.high} high`);
	}
	if (counts.medium > 0) {
		parts.push(`${counts.medium} medium`);
	}
	if (counts.low > 0) {
		parts.push(`${counts.low} low`);
	}
	const detail = parts.length > 0 ? ` (${parts.join(", ")})` : "";
	return `${counts.total} finding${counts.total === 1 ? "" : "s"}${detail}, exit ${exitCode}`;
}

export function buildStepSummaryMarkdown({
	title,
	exitCode,
	counts,
	failOn,
	scannedPaths,
}) {
	const lines = [
		`## ${title}`,
		"",
		"| Metric | Value |",
		"|--------|-------|",
		`| Exit code | ${exitCode} |`,
		`| Findings | ${counts.total} |`,
		`| Critical | ${counts.critical} |`,
		`| High | ${counts.high} |`,
		`| Medium | ${counts.medium} |`,
		`| Low | ${counts.low} |`,
	];

	if (failOn) {
		lines.push(`| Fail threshold | ${failOn} |`);
	}
	if (scannedPaths) {
		lines.push(`| Scanned paths | ${scannedPaths} |`);
	}

	if (exitCode === 1) {
		lines.push(
			"",
			`> Findings at or above **${failOn ?? "configured threshold"}** — see logs or Security tab.`,
		);
	} else if (exitCode !== 0) {
		lines.push("", "> Scan did not complete successfully — see job logs.");
	}

	return `${lines.join("\n")}\n`;
}

export function parseScanOutputFile(format, fileContents) {
	const doc = JSON.parse(fileContents);
	if (format === "json") {
		return parseSummaryFromJson(doc);
	}
	return parseSummaryFromSarif(doc);
}
