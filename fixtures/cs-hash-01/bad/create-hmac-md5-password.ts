import { createHmac } from "crypto";

export function hashPassword(password: string) {
	return createHmac("md5", "pepper").update(password).digest("hex");
}
