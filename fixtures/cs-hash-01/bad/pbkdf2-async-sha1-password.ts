import { pbkdf2 } from "crypto";

export function hashPassword(password: string, salt: string) {
	pbkdf2(password, salt, 1000, 32, "sha1", () => {});
}
