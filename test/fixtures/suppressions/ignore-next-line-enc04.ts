import { createCipheriv } from "crypto";

export function encrypt(data: Buffer, key: Buffer, iv: Buffer) {
	// ciphersins-ignore-next-line CS-ENC-04
	return createCipheriv("aes-128-ecb", key, iv);
}
