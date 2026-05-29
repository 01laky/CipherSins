import { scryptSync } from "crypto";
export function deriveApiKey(apiKey: string, salt: Buffer) {
	return scryptSync(apiKey, salt, 32, { cost: 1024 });
}
