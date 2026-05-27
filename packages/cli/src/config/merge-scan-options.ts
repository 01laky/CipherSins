import {
	assertKnownRuleIds,
	mergeDisabledRuleIds,
	parseRulesConfig,
	resolveDefaultScanRoot,
	type ScanOptions,
	type Severity,
} from "@ciphersins/core";
import type { ParsedScanArgsSuccess } from "../parse-scan-args.js";
import type { CipherSinsConfig } from "./load-config.js";

export interface MergedScanCommandOptions {
	scanOptions: ScanOptions;
	failOn?: Severity;
	failOnDisabled: boolean;
	format: ParsedScanArgsSuccess["format"];
	output?: string;
	quiet: boolean;
}

export function mergeScanOptions(
	parsed: ParsedScanArgsSuccess,
	config: CipherSinsConfig | undefined,
	cwd: string,
): MergedScanCommandOptions {
	const scanPaths =
		parsed.paths.length > 0 ? parsed.paths : [resolveDefaultScanRoot(cwd)];
	const scanOptions: ScanOptions = {
		paths: scanPaths,
		cwd,
	};

	if (config?.include) {
		scanOptions.include = config.include;
	}
	if (config?.exclude) {
		scanOptions.exclude = config.exclude;
	}

	const parsedRules = parseRulesConfig(config?.rules);
	const only = parsed.only ?? config?.only;
	const ignore = mergeDisabledRuleIds(
		config?.ignore,
		parsedRules.disabledRuleIds,
		parsed.ignore,
	);

	if (only) {
		assertKnownRuleIds(only, "only");
		scanOptions.only = only;
	}
	if (ignore) {
		assertKnownRuleIds(ignore, "ignore");
		scanOptions.ignore = ignore;
	}
	if (Object.keys(parsedRules.severities).length > 0) {
		scanOptions.ruleSeverities = parsedRules.severities;
	}
	if (parsed.allowCriticalIgnore) {
		scanOptions.allowCriticalIgnore = true;
	}

	let failOn = parsed.failOn;
	let failOnDisabled = parsed.failOnDisabled;

	if (!failOnDisabled && failOn === undefined && config?.failOn) {
		failOn = config.failOn;
	}

	return {
		scanOptions,
		failOn,
		failOnDisabled,
		format: parsed.format,
		output: parsed.output,
		quiet: parsed.quiet,
	};
}
