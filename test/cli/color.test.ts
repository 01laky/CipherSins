import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	ANSI,
	colorize,
	shouldUseColor,
} from "../../packages/ciphersins/src/color.js";

describe("CS-CLI color helpers", () => {
	const envBackup: Record<string, string | undefined> = {};
	let isTTYBackup: boolean | undefined;

	beforeEach(() => {
		for (const key of ["NO_COLOR", "CI"] as const) {
			envBackup[key] = process.env[key];
			delete process.env[key];
		}
		isTTYBackup = process.stdout.isTTY;
	});

	afterEach(() => {
		for (const key of ["NO_COLOR", "CI"] as const) {
			if (envBackup[key] === undefined) {
				delete process.env[key];
			} else {
				process.env[key] = envBackup[key];
			}
		}
		Object.defineProperty(process.stdout, "isTTY", {
			value: isTTYBackup,
			writable: true,
			configurable: true,
		});
	});

	function setIsTTY(value: boolean | undefined) {
		Object.defineProperty(process.stdout, "isTTY", {
			value,
			writable: true,
			configurable: true,
		});
	}

	it("CS-CLI-COLOR-01 NO_COLOR set disables color", () => {
		process.env.NO_COLOR = "1";
		expect(shouldUseColor()).toBe(false);
	});

	it("CS-CLI-COLOR-02 NO_COLOR empty string does not disable by itself", () => {
		process.env.NO_COLOR = "";
		setIsTTY(true);
		expect(shouldUseColor()).toBe(true);
	});

	it("CS-CLI-COLOR-03 preference.noColor disables color", () => {
		setIsTTY(true);
		expect(shouldUseColor({ noColor: true })).toBe(false);
	});

	it("CS-CLI-COLOR-04 preference.color true forces color on", () => {
		process.env.CI = "true";
		expect(shouldUseColor({ color: true })).toBe(true);
	});

	it("CS-CLI-COLOR-05 preference.color false disables color", () => {
		setIsTTY(true);
		expect(shouldUseColor({ color: false })).toBe(false);
	});

	it("CS-CLI-COLOR-06 CI=true disables color when no explicit preference", () => {
		process.env.CI = "true";
		setIsTTY(true);
		expect(shouldUseColor()).toBe(false);
	});

	it("CS-CLI-COLOR-07 defaults to stdout.isTTY when no env or preference", () => {
		setIsTTY(true);
		expect(shouldUseColor()).toBe(true);
		setIsTTY(false);
		expect(shouldUseColor()).toBe(false);
	});

	it("CS-CLI-COLOR-08 colorize wraps text when enabled", () => {
		expect(colorize("x", ANSI.cyan, true)).toBe(`${ANSI.cyan}x${ANSI.reset}`);
	});

	it("CS-CLI-COLOR-09 colorize returns plain text when disabled", () => {
		expect(colorize("x", ANSI.cyan, false)).toBe("x");
	});
});
