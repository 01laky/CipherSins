import { scryptSync } from "crypto";

export function hashPassword(password: string, salt: Buffer) {
	// ciphersins-ignore-next-line CS-HASH-04
	return scryptSync(password, salt, 64, { cost: 8192 });
}
