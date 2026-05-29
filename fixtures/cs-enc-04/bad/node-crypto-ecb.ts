import crypto from "node:crypto";
export function encrypt(data: Buffer, key: Buffer, iv: Buffer) {
	return crypto.createCipheriv("aes-256-ecb", key, iv);
}
