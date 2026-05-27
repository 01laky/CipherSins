import { runScanCommand } from "./commands/scan.js";
import { ensureBlockingStdout } from "./ensure-blocking-stdout.js";

ensureBlockingStdout();

const HELP = `ciphersins — static scanner for crypto API misuse in Node/TS app code

JWT, timing compares, auth RNG, and password-hashing footguns — not secret scanning.

Usage:
  ciphersins scan [path] [options]

Commands:
  scan [path]   Scan TypeScript/JavaScript files (default path: ./src or .)

Run ciphersins scan --help for scan flags and exit codes.
Docs: https://github.com/01laky/CipherSins/blob/main/docs/cli.md
`;

export const SCAN_HELP = `ciphersins scan [path] [options]

Scan TypeScript/JavaScript files for crypto API misuse.

Options:
  --format pretty|json|sarif   Output format (default: pretty)
  --fail-on none|low|medium|high|critical
                               Exit 1 when findings at or above level exist;
                               "none" disables gating (overrides config)
  --output <file>              Write formatted output to file
  --config <path>              Load JSON config from explicit path
  --no-config                  Ignore ciphersins.config.json in cwd
  --quiet                      Suppress stdout (stderr warnings remain)
  --only <ids>                 Comma-separated rule IDs to run
  --ignore <ids>               Comma-separated rule IDs to skip
  --allow-critical-ignore      Allow inline suppressions for critical findings

Exit codes:
  0  Scan completed; no findings at/above --fail-on threshold (or threshold absent)
  1  Scan completed; findings at/above --fail-on threshold
  2  Usage error, config error, or scan failure (parse/I/O)

Config discovery (when --no-config is not set):
  1. --config <path> if provided
  2. ./ciphersins.config.json in cwd if present

Examples:
  ciphersins scan ./src
  ciphersins scan --format json --fail-on high
  ciphersins scan --format sarif --output results.sarif --fail-on high
  ciphersins scan --fail-on none

Docs: https://github.com/01laky/CipherSins/blob/main/docs/cli.md
`;

async function main(): Promise<void> {
	const [, , command, ...rest] = process.argv;

	if (!command || command === "--help" || command === "-h") {
		process.stdout.write(HELP);
		process.exit(0);
	}

	if (command === "--version" || command === "-v") {
		process.stdout.write("0.9.1\n");
		process.exit(0);
	}

	if (command !== "scan") {
		process.stderr.write(`Unknown command: ${command}\n\n${HELP}`);
		process.exit(2);
	}

	if (rest[0] === "--help" || rest[0] === "-h") {
		process.stdout.write(SCAN_HELP);
		process.exit(0);
	}

	const exitCode = await runScanCommand(rest);
	process.exit(exitCode);
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error);
	process.stderr.write(`${message}\n`);
	process.exit(2);
});
