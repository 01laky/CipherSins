export type {
	Finding,
	Rule,
	RuleContext,
	ScanOptions,
	ScanResult,
	Severity,
} from "./types.js";
export {
	DEFAULT_EXCLUDE,
	DEFAULT_INCLUDE,
	DEFAULT_MAX_FILE_SIZE_BYTES,
	SEVERITIES,
} from "./types.js";
export type { SkippedPath, SkippedPathReason } from "./types.js";
export { VERSION } from "./version.js";

export {
	ParseSourceFileError,
	parseSourceFile,
	stripUtf8Bom,
} from "./parse-source-file.js";
export { createRuleContext } from "./create-rule-context.js";
export {
	getLineSnippet,
	getPositionForLineColumn,
	formatRelativePath,
} from "./get-line-snippet.js";
export { expandUserPath } from "./expand-user-path.js";
export { resolveDefaultScanRoot, resolveFiles } from "./resolve-files.js";
export { runRules } from "./run-rules.js";
export { RuleExecutionError } from "./rule-execution-error.js";
export { createEmptySummary, scan, summarizeFindings } from "./scan.js";
export {
	RULE_IDS,
	assertKnownRuleIds,
	applyRuleSeverityOverrides,
	isKnownRuleId,
	mergeDisabledRuleIds,
	parseRuleConfigValue,
	parseRulesConfig,
	selectRules,
	type ParsedRulesConfig,
	type RuleConfigValue,
} from "./rule-config.js";
export {
	applySuppressions,
	parseSuppressions,
	type Suppression,
	type SuppressionParseResult,
} from "./suppressions.js";
export { formatJson, type FormatJsonOptions } from "./reporting/format-json.js";
export {
	formatSarif,
	type FormatSarifOptions,
} from "./reporting/format-sarif.js";
export { findingPrimaryLocationLineHash } from "./reporting/sarif-fingerprint.js";
export {
	isSeverity,
	severityRank,
	severityToSarifLevel,
	summaryExceedsFailOn,
} from "./reporting/severity.js";
export { sortFindings } from "./reporting/sort-findings.js";
export {
	allRules,
	csJwt01Rule,
	csJwt02Rule,
	csJwt03Rule,
	csJwt04Rule,
	csJwt05Rule,
	csJwt06Rule,
	csCmp01Rule,
	csRng01Rule,
	csRng02Rule,
	csHash01Rule,
	csHash02Rule,
	csHash03Rule,
	csHash04Rule,
	csHash05Rule,
	csEnc01Rule,
	csEnc02Rule,
	csEnc03Rule,
	csEnc04Rule,
	csDec01Rule,
} from "./rules/index.js";
export { PBKDF2_MIN_ITERATIONS } from "./rules/helpers/pbkdf2-iterations.js";
export {
	SCRYPT_MIN_COST,
	SCRYPT_MIN_BLOCK_SIZE,
	SCRYPT_MIN_PARALLELIZATION,
} from "./rules/helpers/scrypt-cost.js";
export {
	ARGON2_MIN_TIME_COST,
	ARGON2_MIN_MEMORY_COST,
} from "./rules/helpers/argon2-params.js";
export { RNG_MIN_AUTH_BYTES } from "./rules/helpers/random-bytes-length.js";
