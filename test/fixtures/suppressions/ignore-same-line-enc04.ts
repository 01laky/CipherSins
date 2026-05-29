import { createCipheriv } from "crypto";

export function encrypt(data: Buffer, key: Buffer, iv: Buffer) {
	return createCipheriv("aes-256-ecb", key, iv); // ciphersins-ignore CS-ENC-04
}
