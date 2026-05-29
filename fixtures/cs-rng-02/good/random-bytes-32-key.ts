import { randomBytes } from "crypto";
export function generateSecretKey() {
	return randomBytes(32);
}
