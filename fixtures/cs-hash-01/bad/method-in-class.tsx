import crypto from "crypto";

export class Auth {
	hashPassword(password: string) {
		return crypto.createHash("md5").update(password).digest("hex");
	}
}
