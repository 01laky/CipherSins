import { createHash } from "crypto";

export function hashPassword(password: string) {
	return createHash("MD5").update(password).digest("hex");
}
