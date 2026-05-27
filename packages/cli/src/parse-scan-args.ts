import { parseArgs } from "node:util";
import {
	assertKnownRuleIds,
	isSeverity,
	type Severity,
} from "@ciphersins/core";

export type OutputFormat = "pretty" | "json" | "sarif";

export interface ParsedScanArgsSuccess {
	ok: true;
	paths: string[];
	format: OutputFormat;
	failOn?: Severity;
	failOnDisabled: boolean;
	output?: string;
	config?: string;
	noConfig: boolean;
	quiet: boolean;
	only?: string[];
	ignore?: string[];
	allowCriticalIgnore: boolean;
}

export interface ParsedScanArgsFailure {
	ok: false;
	message: string;
}

export type ParsedScanArgs = ParsedScanArgsSuccess | ParsedScanArgsFailure;

const VALID_FORMATS = new Set<OutputFormat>(["pretty", "json", "sarif"]);

function normalizeArgs(args: string[]): string[] {
	const normalized: string[] = [];
	for (let index = 0; index < args.length; index += 1) {
		const token = args[index];
		if (token === "--failOn") {
			normalized.push("--fail-on", args[index + 1] ?? "");
			index += 1;
			continue;
		}
		if (token.startsWith("--failOn=")) {
			normalized.push(`--fail-on=${token.slice("--failOn=".length)}`);
			continue;
		}
		normalized.push(token);
	}
	return normalized;
}

function parseRuleIdList(value: string, label: string): string[] {
	const ruleIds = value
		.split(",")
		.map((part) => part.trim())
		.filter(Boolean);
	if (ruleIds.length === 0) {
		throw new Error(`invalid ${label}: expected at least one rule id`);
	}
	assertKnownRuleIds(ruleIds, label);
	return ruleIds;
}

export function parseScanArgs(args: string[]): ParsedScanArgs {
	const normalized = normalizeArgs(args);

	try {
		const { values, positionals } = parseArgs({
			args: normalized,
			options: {
				"fail-on": { type: "string" },
				format: { type: "string", default: "pretty" },
				output: { type: "string" },
				config: { type: "string" },
				"no-config": { type: "boolean", default: false },
				quiet: { type: "boolean", default: false },
				only: { type: "string" },
				ignore: { type: "string" },
				"allow-critical-ignore": { type: "boolean", default: false },
			},
			allowPositionals: true,
			strict: true,
		});

		const format = values.format ?? "pretty";
		if (!VALID_FORMATS.has(format as OutputFormat)) {
			return {
				ok: false,
				message: `invalid --format value: ${format}`,
			};
		}

		let failOnDisabled = false;
		let failOn: Severity | undefined;

		if (values["fail-on"] !== undefined) {
			if (values["fail-on"] === "none") {
				failOnDisabled = true;
			} else if (isSeverity(values["fail-on"])) {
				failOn = values["fail-on"];
			} else {
				return {
					ok: false,
					message: `invalid --fail-on value: ${values["fail-on"]}`,
				};
			}
		}

		let only: string[] | undefined;
		let ignore: string[] | undefined;

		try {
			if (values.only !== undefined) {
				only = parseRuleIdList(values.only, "--only");
			}
			if (values.ignore !== undefined) {
				ignore = parseRuleIdList(values.ignore, "--ignore");
			}
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			return { ok: false, message };
		}

		return {
			ok: true,
			paths: positionals,
			format: format as OutputFormat,
			failOn,
			failOnDisabled,
			output: values.output,
			config: values.config,
			noConfig: values["no-config"] ?? false,
			quiet: values.quiet ?? false,
			only,
			ignore,
			allowCriticalIgnore: values["allow-critical-ignore"] ?? false,
		};
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return { ok: false, message };
	}
}
