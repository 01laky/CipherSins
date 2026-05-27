import { pathToFileURL } from "node:url";
import { formatRelativePath } from "../get-line-snippet.js";
import { allRules } from "../rules/index.js";
import type { Finding, ScanResult } from "../types.js";
import { findingPrimaryLocationLineHash } from "./sarif-fingerprint.js";
import { severityToSarifLevel } from "./severity.js";
import { sortFindings } from "./sort-findings.js";

const REPO_BASE = "https://github.com/01laky/CipherSins/blob/main/docs/rules";

export interface FormatSarifOptions {
	cwd: string;
	toolVersion: string;
}

function ruleHelpUrl(ruleId: string): string {
	return `${REPO_BASE}/${ruleId}.md`;
}

function ruleHelpText(ruleId: string, title: string): string {
	const helpUrl = ruleHelpUrl(ruleId);
	return `See [${ruleId}](${helpUrl}) — ${title}.`;
}

function buildDriverRules(toolVersion: string) {
	return allRules.map((rule) => ({
		id: rule.id,
		name: rule.title,
		shortDescription: { text: rule.title },
		fullDescription: { text: rule.title },
		helpUri: ruleHelpUrl(rule.id),
		help: {
			text: ruleHelpText(rule.id, rule.title),
		},
		defaultConfiguration: {
			level: severityToSarifLevel(rule.severity),
		},
	}));
}

function findingToSarifResult(finding: Finding, cwd: string) {
	const relativeFile = formatRelativePath(finding.file, cwd).replace(
		/\\/g,
		"/",
	);

	return {
		ruleId: finding.ruleId,
		level: severityToSarifLevel(finding.severity),
		message: { text: finding.message },
		partialFingerprints: {
			primaryLocationLineHash: findingPrimaryLocationLineHash(finding, cwd),
		},
		locations: [
			{
				physicalLocation: {
					artifactLocation: {
						uri: relativeFile,
						uriBaseId: "%WORKINGDIR%",
					},
					region: {
						startLine: finding.line,
						startColumn: finding.column,
						snippet: { text: finding.snippet ?? "" },
					},
				},
			},
		],
	};
}

function workingDirectoryUri(cwd: string): string {
	const href = pathToFileURL(cwd).href;
	return href.endsWith("/") ? href : `${href}/`;
}

export function formatSarif(
	result: ScanResult,
	options: FormatSarifOptions | string,
	toolVersion?: string,
): string {
	const opts: FormatSarifOptions =
		typeof options === "string"
			? { cwd: options, toolVersion: toolVersion ?? "0.9.1" }
			: options;

	return `${JSON.stringify(
		{
			$schema: "https://json.schemastore.org/sarif-2.1.0.json",
			version: "2.1.0",
			runs: [
				{
					tool: {
						driver: {
							name: "CipherSins",
							version: opts.toolVersion,
							informationUri: "https://github.com/01laky/CipherSins",
							rules: buildDriverRules(opts.toolVersion),
						},
					},
					results: sortFindings(result.findings).map((finding) =>
						findingToSarifResult(finding, opts.cwd),
					),
					columnKind: "utf16CodeUnits",
					originalUriBaseIds: {
						"%WORKINGDIR%": {
							uri: workingDirectoryUri(opts.cwd),
						},
					},
				},
			],
		},
		null,
		2,
	)}\n`;
}
