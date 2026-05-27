import crypto from "node:crypto";

export function hashUserPassword(password: string) {
	return crypto.createHash("sha1").update(password).digest("hex");
}
