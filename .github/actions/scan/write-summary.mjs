import fs from "node:fs";
import {
	buildStepSummaryMarkdown,
	formatOneLineSummary,
	parseScanOutputFile,
} from "./summary.mjs";

const [format, file, exitCodeStr, title, failOn, paths, writeSummaryStr] =
	process.argv.slice(2);

const exitCode = Number(exitCodeStr);
const writeSummary = writeSummaryStr === "true";
const contents = fs.readFileSync(file, "utf8");
const counts = parseScanOutputFile(format, contents);
const summaryLine = formatOneLineSummary(counts, exitCode);

if (writeSummary && process.env.GITHUB_STEP_SUMMARY) {
	const md = buildStepSummaryMarkdown({
		title,
		exitCode,
		counts,
		failOn: failOn === "none" ? undefined : failOn,
		scannedPaths: paths,
	});
	fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
}

console.log(JSON.stringify({ counts, summaryLine }));
