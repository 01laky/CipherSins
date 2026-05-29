import argon2 from "argon2";
const t = 2;
export async function hashPassword(password: string) {
	return argon2.hash(password, { timeCost: t, memoryCost: 65536 });
}
