import { createCipheriv } from "crypto";

export function encrypt(data: Buffer, key: Buffer, iv: Buffer) {
	// ciphersins-ignore-next-line CS-ENC-03
	return createCipheriv("bf", key, iv);
}
