import { createHash } from "crypto";

export function hashPassword(password: string, algorithm: string) {
	return createHash(algorithm).update(password).digest("hex");
}
