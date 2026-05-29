import argon2 from "argon2";
export async function hashApiKey(apiKey: string) {
	return argon2.hash(apiKey, { timeCost: 1, memoryCost: 4096 });
}
