import { createHash } from "crypto";

export function processCredentials(password: string) {
	const hashedPassword = createHash("md5").update(password).digest("hex");
	return hashedPassword;
}
