import { scryptSync } from "crypto";
export function hashPassword(password: string, salt: Buffer) {
	return scryptSync(password, salt, 64, { cost: 16384, blockSize: 4 });
}
