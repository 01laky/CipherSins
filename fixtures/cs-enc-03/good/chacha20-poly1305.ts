import { createCipheriv, randomBytes } from "crypto";
export function encrypt(data: Buffer, key: Buffer) {
	return createCipheriv("chacha20-poly1305", key, randomBytes(12));
}
