import crypto from "crypto";
export function generateAuthToken() {
	return crypto.randomBytes(4).toString("hex");
}
