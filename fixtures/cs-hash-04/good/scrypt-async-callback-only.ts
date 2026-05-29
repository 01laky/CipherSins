import { scrypt } from "crypto";
export function hashPassword(
	password: string,
	salt: Buffer,
	cb: (err: Error | null, key: Buffer) => void,
) {
	scrypt(password, salt, 64, cb);
}
