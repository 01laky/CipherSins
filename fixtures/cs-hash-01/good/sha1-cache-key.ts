import crypto from "crypto";

export function buildCacheKey(id: string) {
	const cacheKey = crypto.createHash("sha1").update(id).digest("hex");
	return cacheKey;
}
