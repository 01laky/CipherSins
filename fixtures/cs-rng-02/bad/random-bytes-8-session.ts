import { randomBytes } from "crypto";
export function generateSessionToken() {
	return randomBytes(8).toString("hex");
}
