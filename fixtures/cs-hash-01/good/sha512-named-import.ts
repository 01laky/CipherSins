import { createHash } from "crypto";

export function hashPassword(password: string) {
	return createHash("sha512").update(password).digest("hex");
}
