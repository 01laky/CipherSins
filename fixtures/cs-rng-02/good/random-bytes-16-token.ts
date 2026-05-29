import { randomBytes } from "crypto";
export function generateSessionToken() {
	return randomBytes(16).toString("hex");
}
