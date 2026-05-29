import { scryptSync } from "crypto";
const config = { cost: 8192 };
export function hashPassword(password: string, salt: Buffer) {
	return scryptSync(password, salt, 64, config);
}
