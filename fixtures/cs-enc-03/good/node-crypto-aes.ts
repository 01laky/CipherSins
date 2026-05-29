import crypto from "node:crypto";
export function encrypt(data: Buffer, key: Buffer) {
	return crypto.createCipheriv("aes-256-gcm", key, crypto.randomBytes(12));
}
