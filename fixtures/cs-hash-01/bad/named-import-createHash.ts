import { createHash } from "crypto";

export function hashPassword(password: string) {
	return createHash("md5").update(password).digest("hex");
}
