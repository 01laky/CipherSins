import { createCipheriv, randomBytes } from "crypto";
export function encrypt(data: Buffer, key: Buffer, algorithm: string) {
	return createCipheriv(algorithm, key, randomBytes(16));
}
