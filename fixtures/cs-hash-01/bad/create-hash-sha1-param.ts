import { createHash } from "crypto";

export function authenticate(password: string) {
	return createHash("sha1").update(password).digest("hex");
}
