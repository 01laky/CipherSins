import crypto from "crypto";

export function computeFileChecksum(data: string) {
	return crypto.createHash("md5").update(data).digest("hex");
}
