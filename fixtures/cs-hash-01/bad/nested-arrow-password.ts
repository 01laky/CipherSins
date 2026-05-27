import crypto from "crypto";

export function wrap(password: string) {
	const hash = () => crypto.createHash("md5").update(password).digest("hex");
	return hash();
}
