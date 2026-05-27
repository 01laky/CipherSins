import fs from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import path from "node:path";
import {
	formatJson,
	formatSarif,
	scan,
	summaryExceedsFailOn,
} from "@ciphersins/core";
import { loadConfig } from "../config/load-config.js";
import { mergeScanOptions } from "../config/merge-scan-options.js";
import { ensureBlockingStdout } from "../ensure-blocking-stdout.js";
import { formatFailSummary } from "../format-fail-summary.js";
import { formatPretty } from "../formatters/pretty.js";
import { parseScanArgs } from "../parse-scan-args.js";

ensureBlockingStdout();

export const TOOL_VERSION = "0.9.1";

function writeOutputFile(outputPath: string, payload: string): void {
	fs.mkdirSync(path.dirname(outputPath), { recursive: true });
	fs.writeFileSync(outputPath, payload, "utf8");
}

async function writeStdout(payload: string): Promise<void> {
	if (payload.length === 0) {
		return;
	}
	await pipeline(Readable.from([payload]), process.stdout, { end: false });
}

function formatScanResult(
	result: Awaited<ReturnType<typeof scan>>,
	format: "pretty" | "json" | "sarif",
	cwd: string,
): string {
	switch (format) {
		case "json":
			return formatJson(result, { cwd, toolVersion: TOOL_VERSION });
		case "sarif":
			return formatSarif(result, { cwd, toolVersion: TOOL_VERSION });
		case "pretty":
			return formatPretty(result, cwd);
	}
}

export async function runScanCommand(args: string[]): Promise<number> {
	const parsed = parseScanArgs(args);
	if (!parsed.ok) {
		process.stderr.write(`error: ${parsed.message}\n`);
		return 2;
	}

	const cwd = process.cwd();

	let config;
	try {
		config = loadConfig({
			cwd,
			config: parsed.config,
			noConfig: parsed.noConfig,
		});
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		process.stderr.write(`error: ${message}\n`);
		return 2;
	}

	const merged = mergeScanOptions(parsed, config, cwd);

	try {
		const result = await scan(merged.scanOptions);

		if (result.skippedPaths.length > 0) {
			for (const skipped of result.skippedPaths) {
				process.stderr.write(`warning: skipped missing path ${skipped}\n`);
			}
		}

		const payload = formatScanResult(result, merged.format, cwd);

		if (merged.output) {
			writeOutputFile(path.resolve(cwd, merged.output), payload);
		} else if (!merged.quiet) {
			await writeStdout(payload);
		}

		const shouldFail = summaryExceedsFailOn(
			result.summary,
			merged.failOn,
			merged.failOnDisabled,
		);

		if (shouldFail && merged.failOn) {
			process.stderr.write(
				`${formatFailSummary(result.summary, merged.failOn)}\n`,
			);
			return 1;
		}

		return 0;
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		process.stderr.write(`error: ${message}\n`);
		return 2;
	}
}
