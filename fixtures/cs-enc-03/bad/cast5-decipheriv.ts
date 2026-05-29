import { createDecipheriv } from "crypto";
export function decrypt(data: Buffer, key: Buffer, iv: Buffer) {
	return createDecipheriv("cast5-cbc", key, iv);
}
