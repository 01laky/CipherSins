import argon2 from "argon2";
export async function hashPassword(password: string) {
	return argon2.hash(password, { timeCost: 3, memoryCost: 4096 });
}
