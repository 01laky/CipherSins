import { createHash } from "crypto";

export function storePassword(password: string) {
	const md5Hash = createHash("md5").update(password).digest("hex");
	const sha1Hash = createHash("sha1").update(password).digest("hex");
	return { md5Hash, sha1Hash };
}
