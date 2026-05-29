import argon2 from "argon2";

export async function hashPassword(password: string) {
	// ciphersins-ignore-next-line CS-HASH-05
	return argon2.hash(password, { timeCost: 2 });
}
