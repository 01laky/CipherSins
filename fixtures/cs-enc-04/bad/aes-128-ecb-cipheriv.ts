import { createCipheriv } from "crypto";
export function encrypt(data: Buffer, key: Buffer, iv: Buffer) {
	return createCipheriv("aes-128-ecb", key, iv);
}
