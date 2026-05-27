import { scryptSync } from "crypto";

export function hashPassword(password: string, salt: string) {
	return scryptSync(password, salt, 64);
}
