import { hashSync } from "argon2";
export function hashPassword(password: string) {
	return hashSync(password, { timeCost: 2, memoryCost: 65536 });
}
