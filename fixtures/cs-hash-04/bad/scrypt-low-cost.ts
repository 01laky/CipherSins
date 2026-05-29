import { scryptSync } from "crypto";
export function hashPassword(password: string, salt: Buffer) {
	return scryptSync(password, salt, 64, { cost: 8192 });
}
