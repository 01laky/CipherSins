import { createHash } from "crypto";

export function hashPassword(password: string) {
	return createHash("sha-1").update(password).digest("hex");
}
