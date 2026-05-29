import { createCipheriv, randomBytes } from "crypto";
export function encrypt(data: Buffer, key: Buffer) {
	return createCipheriv("des-cbc", key, randomBytes(8));
}
