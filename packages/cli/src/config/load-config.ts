import fs from "node:fs";
import path from "node:path";
import { isSeverity, type Severity } from "@ciphersins/core";

export interface CipherSinsConfig {
	include?: string[];
	exclude?: string[];
	failOn?: Severity;
}

export function loadConfigFile(configPath: string): CipherSinsConfig {
	const raw = fs.readFileSync(configPath, "utf8");
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch (error) {
		const detail = error instanceof Error ? error.message : String(error);
		throw new Error(`invalid config: ${detail}`);
	}

	if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new Error("invalid config: expected a JSON object");
	}

	const record = parsed as Record<string, unknown>;
	const config: CipherSinsConfig = {};

	if (record.include !== undefined) {
		if (!Array.isArray(record.include) || !record.include.every(isString)) {
			throw new Error("invalid config: include must be a string array");
		}
		config.include = record.include;
	}

	if (record.exclude !== undefined) {
		if (!Array.isArray(record.exclude) || !record.exclude.every(isString)) {
			throw new Error("invalid config: exclude must be a string array");
		}
		config.exclude = record.exclude;
	}

	if (record.failOn !== undefined) {
		if (typeof record.failOn !== "string" || !isSeverity(record.failOn)) {
			throw new Error(`invalid config: invalid failOn value: ${record.failOn}`);
		}
		config.failOn = record.failOn;
	}

	return config;
}

function isString(value: unknown): value is string {
	return typeof value === "string";
}

export function discoverConfigPath(cwd: string): string | undefined {
	const defaultPath = path.join(cwd, "ciphersins.config.json");
	return fs.existsSync(defaultPath) ? defaultPath : undefined;
}

export function resolveConfigPath(options: {
	cwd: string;
	config?: string;
	noConfig: boolean;
}): string | undefined {
	if (options.noConfig) {
		return undefined;
	}
	if (options.config) {
		return path.resolve(options.cwd, options.config);
	}
	return discoverConfigPath(options.cwd);
}

export function loadConfig(options: {
	cwd: string;
	config?: string;
	noConfig: boolean;
}): CipherSinsConfig | undefined {
	const configPath = resolveConfigPath(options);
	if (!configPath) {
		return undefined;
	}
	if (!fs.existsSync(configPath)) {
		throw new Error(`config file not found: ${configPath}`);
	}
	return loadConfigFile(configPath);
}
