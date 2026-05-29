import { hash } from "@node-rs/argon2";
export async function hashPassword(password: string) {
	return hash(password, { timeCost: 2, memoryCost: 65536 });
}
