import { randomBytes } from "crypto";
const n = 12;
export function generateSessionToken() {
	return randomBytes(n).toString("hex");
}
