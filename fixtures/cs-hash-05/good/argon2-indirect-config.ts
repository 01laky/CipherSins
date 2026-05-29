import argon2 from "argon2";
const config = { timeCost: 2, memoryCost: 65536 };
export async function hashPassword(password: string) {
	return argon2.hash(password, config);
}
