import { createDecipheriv } from "crypto";
export function decrypt(data: Buffer, key: Buffer, iv: Buffer) {
	return createDecipheriv("aes-256-ecb", key, iv);
}
