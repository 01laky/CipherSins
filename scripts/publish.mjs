#!/usr/bin/env node
/**
 * Local npm publish for @ciphersins/core and ciphersins.
 *
 * Usage:
 *   npm run publish:npm              # verify + pack:check + publish both packages
 *   npm run publish:npm -- --dry-run   # pack:check only, no registry upload
 *   npm run publish:npm -- --skip-verify
 *
 * Auth (pick one):
 *   npm login
 *   export NODE_AUTH_TOKEN=npm_...
 */
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const skipVerify = args.includes("--skip-verify");
const noProvenance = args.includes("--no-provenance");

const pnpmBin = path.join(rootDir, "node_modules/.bin/pnpm");

function pnpmArgs(subcommandArgs) {
	if (fs.existsSync(pnpmBin)) {
		return { command: pnpmBin, args: subcommandArgs };
	}
	return { command: "npx", args: ["--yes", "pnpm@9.15.9", ...subcommandArgs] };
}

function run(command, commandArgs, options = {}) {
	execFileSync(command, commandArgs, {
		cwd: rootDir,
		stdio: "inherit",
		...options,
	});
}

function runPnpm(subcommandArgs) {
	const { command, args: argv } = pnpmArgs(subcommandArgs);
	run(command, argv);
}

function readJson(relativePath) {
	return JSON.parse(fs.readFileSync(path.join(rootDir, relativePath), "utf8"));
}

function npmWhoami() {
	const result = spawnSync("npm", ["whoami"], {
		cwd: rootDir,
		encoding: "utf8",
		env: process.env,
	});
	return result.status === 0 ? result.stdout.trim() : null;
}

function assertVersionsAligned() {
	const rootVersion = readJson("package.json").version;
	const coreVersion = readJson("packages/core/package.json").version;
	const cliVersion = readJson("packages/cli/package.json").version;

	if (rootVersion !== coreVersion || rootVersion !== cliVersion) {
		console.error(
			`publish: version mismatch — root ${rootVersion}, core ${coreVersion}, cli ${cliVersion}`,
		);
		process.exit(1);
	}

	return rootVersion;
}

function assertNpmAuth() {
	if (process.env.NODE_AUTH_TOKEN?.trim()) {
		console.log("publish: using NODE_AUTH_TOKEN");
		return;
	}

	const user = npmWhoami();
	if (!user) {
		console.error(
			"publish: not logged in to npm.\n" +
				"  Run: npm login\n" +
				"  Or:  export NODE_AUTH_TOKEN=npm_...",
		);
		process.exit(1);
	}

	console.log(`publish: npm user ${user}`);
}

function publishPackage(filter) {
	const publishArgs = [
		"--filter",
		filter,
		"publish",
		"--access",
		"public",
		"--no-git-checks",
	];
	if (!noProvenance) {
		publishArgs.push("--provenance");
	}
	if (dryRun) {
		publishArgs.push("--dry-run");
	}

	console.log(`\npublish: ${dryRun ? "dry-run" : "upload"} ${filter}`);
	runPnpm(publishArgs);
}

const version = assertVersionsAligned();
console.log(`publish: CipherSins v${version}`);

if (!dryRun) {
	assertNpmAuth();
}

if (!skipVerify && !dryRun) {
	console.log("\npublish: running npm run verify …");
	run("npm", ["run", "verify"]);
}

console.log("\npublish: running npm run pack:check …");
run("npm", ["run", "pack:check"]);

if (dryRun) {
	console.log("\npublish: dry-run OK — pack:check passed, no packages uploaded");
	process.exit(0);
}

publishPackage("@ciphersins/core");
publishPackage("ciphersins");

console.log("\npublish: OK — both packages published to npm");
console.log(`  npx ciphersins@${version} --version`);
console.log(`  npm view @ciphersins/core version`);
