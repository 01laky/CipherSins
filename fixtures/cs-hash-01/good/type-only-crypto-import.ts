import type crypto from "crypto";

export function hashPassword(password: string, expected: string) {
	return password === expected;
}

void crypto;
