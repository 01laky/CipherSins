import { createCipheriv, randomBytes } from "crypto";
export function encrypt(data: Buffer) {
	return createCipheriv("des-cbc", "hardcoded-key-16bytes!", randomBytes(8));
}
