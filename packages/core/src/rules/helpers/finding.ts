import ts from "typescript";
import { getLineSnippet } from "../../get-line-snippet.js";
import type { Finding, Severity } from "../../types.js";

export interface CreateFindingOptions {
	ruleId: string;
	message: string;
	severity: Severity;
	helpUrl: string;
	filePath: string;
	sourceFile: ts.SourceFile;
	node: ts.Node;
}

export function createFinding(options: CreateFindingOptions): Finding {
	const { line, character } = options.sourceFile.getLineAndCharacterOfPosition(
		options.node.getStart(options.sourceFile),
	);
	const findingLine = line + 1;

	return {
		ruleId: options.ruleId,
		message: options.message,
		file: options.filePath,
		line: findingLine,
		column: character + 1,
		severity: options.severity,
		snippet: getLineSnippet(options.sourceFile, findingLine),
		helpUrl: options.helpUrl,
	};
}
