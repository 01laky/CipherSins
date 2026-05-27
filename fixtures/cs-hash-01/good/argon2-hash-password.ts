import argon2 from "argon2";

export function hashPassword(password: string) {
	return argon2.hash(password);
}
